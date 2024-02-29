#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <ft/stdlib.h>
#include <ft/string.h>
#include <ft/math.h>
#include <ft/getopt.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/param.h>

const char *prog_name = NULL;
volatile sig_atomic_t exit_now = 0;

#define PING_MAX_IPV4_LEN 65535
#define PING_IPV4_HDR_LEN 20
#define PING_ICMP_HDR_LEN 8
#define PING_MAX_DATALEN \
	(PING_MAX_IPV4_LEN - PING_IPV4_HDR_LEN - PING_ICMP_HDR_LEN)

struct icmpmsg {
	struct icmphdr hdr;
	uint8_t data[];
};

struct ping_opts {
	const char *host;
	uint32_t datalen;
	uint32_t count;
	uint16_t preload;
	unsigned timeout;
	unsigned linger;
	unsigned interval;
	uint8_t padding;
	bool verbose;
	bool flood;
	bool add_time;
};

struct ping_rts {
	int sockfd;
	struct sockaddr_in addr;
	char numaddr[INET_ADDRSTRLEN];

	uint64_t nxmit;
	uint64_t nrecv;

	float min_rtt;
	float avg_rtt;
	float max_rtt;
	float var_rtt;

	const struct ping_opts *opts;
};

#define PING_RECVMSG_ERR 1
#define PING_RECVMSG_TRUNC 2

__attribute__((format(printf, 3, 4))) static void error(int status, int errnum,
							const char *fmt, ...)
{
	fprintf(stderr, "%s: ", prog_name);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (errnum)
		fprintf(stderr, ": %s", strerror(errnum));
	fprintf(stderr, "\n");

	if (status)
		exit(status);
}

static int read_reply(int sockfd, struct icmpmsg *dest, size_t destlen,
		      int *ttl, void *addr, size_t addrlen, struct timeval *ts,
		      bool poll)
{
	int res = 0;
	struct iovec iov;
	iov.iov_base = dest;
	iov.iov_len = destlen;

	char cbuf[512];

	struct msghdr msg = {
		.msg_name = addr,
		.msg_namelen = addrlen,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
		.msg_flags = 0,
	};

	ssize_t nread = recvmsg(sockfd, &msg, poll * MSG_DONTWAIT);
	if (nread < 0) {
		if (errno != EAGAIN && errno != EINTR)
			error(0, errno, "recvmsg");
		res |= PING_RECVMSG_ERR;
		return res;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		res |= PING_RECVMSG_TRUNC;
		return res;
	}

	assert(ttl);
	*ttl = 0;

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_TTL) {
			ft_memcpy(ttl, CMSG_DATA(cmsg), sizeof(*ttl));
		} else if (cmsg->cmsg_level == SOL_SOCKET &&
			   cmsg->cmsg_type == SCM_TIMESTAMP) {
			ft_memcpy(ts, CMSG_DATA(cmsg), sizeof(*ts));
		}
		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}
	return res;
}

//https://en.wikipedia.org/w/index.php?title=Algorithms_for_calculating_variance&oldid=1198125194#Welford's_online_algorithm
static void update_stats(struct ping_rts *rts, float rtt)
{
	rts->min_rtt = ft_fminf(rts->min_rtt, rtt);
	rts->max_rtt = ft_fmaxf(rts->max_rtt, rtt);

	float old_avg = rts->avg_rtt;

	rts->avg_rtt = (rtt + rts->nrecv * rts->avg_rtt) / (rts->nrecv + 1);

	if (rts->nrecv) {
		rts->var_rtt =
			rts->var_rtt + ((rtt - old_avg) * (rtt - rts->avg_rtt) -
					rts->var_rtt) /
					       rts->nrecv;
	} else {
		rts->var_rtt = (rtt - rts->avg_rtt) * (rtt - rts->avg_rtt);
	}

	rts->nrecv += 1;
}

static void print_ping(const struct ping_rts *rts, uint16_t nseq, int ttl,
		       float rtt)
{
	if (!rts->opts->flood) {
		printf("%zu bytes from %s: icmp_seq=%hu ttl=%i",
		       rts->opts->datalen + sizeof(struct icmphdr),
		       rts->numaddr, nseq, ttl);

		if (rts->opts->add_time)
			printf(" time=%.3f ms", rtt);
		printf("\n");
	} else {
		write(1, "\x08", 1);
	}
}

static float millis_elapsed(struct timeval start, struct timeval end)
{
	return (end.tv_sec - start.tv_sec) * 1000.0f +
	       (end.tv_usec - start.tv_usec) / 1000.0f;
}

static uint16_t inet_checksum(const void *src, size_t len)
{
	const uint16_t *s = src;

	assert(len <= 0x10000); // will not overflow below this length
	uint32_t sum = 0;
	while (len >= 2) {
		sum += *s++;
		len -= 2;
	}
	if (len)
		sum += (uint16_t)(*(uint8_t *)s) << 8;

	while (sum & ~0xFFFF)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)~sum;
}

static void recv_replies(struct ping_rts *rts, struct icmpmsg *replybuf,
			 size_t buflen)
{
	bool poll = rts->opts->flood;

	while (rts->nrecv < rts->nxmit) {
		int ttl;
		struct sockaddr_in from;
		struct timeval ts;
		int flags = read_reply(rts->sockfd, replybuf, buflen, &ttl,
				       &from, sizeof(from), &ts, poll);

		poll = true;

		if (flags & PING_RECVMSG_ERR)
			break;
		if (flags & PING_RECVMSG_TRUNC ||
		    replybuf->hdr.type != ICMP_ECHOREPLY ||
		    replybuf->hdr.code || inet_checksum(replybuf, buflen))
			continue;
		assert(!flags);

		float rtt = 0.0f;

		if (rts->opts->add_time) {
			struct timeval sent;
			ft_memcpy(&sent, replybuf->data, sizeof(sent));
			rtt = millis_elapsed(sent, ts);
		}

		uint16_t nseq = ntohs(replybuf->hdr.un.echo.sequence);

		update_stats(rts, rtt);
		print_ping(rts, nseq, ttl, rtt);
	}
}

static void init_echo(struct icmpmsg *echo, size_t n, uint8_t padding)
{
	echo->hdr.type = ICMP_ECHO;
	echo->hdr.code = 0;
	echo->hdr.checksum = 0;
	echo->hdr.un.echo.id = 0;
	echo->hdr.un.echo.sequence = 0;
	memset(echo->data, padding, n - sizeof(echo->hdr));
}

static void gettimeofday_or_err(struct timeval *restrict tv,
				struct timezone *restrict tz)
{
	if (gettimeofday(tv, tz))
		error(EXIT_FAILURE, errno, "gettimeofday");
}

static void prepare_echo(struct ping_rts *rts, struct icmpmsg *echobuf,
			 uint16_t nseq)
{
	echobuf->hdr.un.echo.sequence = htons(nseq);

	if (rts->opts->add_time) {
		struct timeval now;
		gettimeofday_or_err(&now, NULL);
		ft_memcpy(echobuf->data, &now, sizeof(now));
	}
}

static void send_echo(struct ping_rts *rts, struct icmpmsg *echobuf,
		      size_t buflen, uint16_t nseq)
{
	prepare_echo(rts, echobuf, nseq);

	ssize_t nsent = sendto(rts->sockfd, echobuf, buflen, 0,
			       (const struct sockaddr *)&rts->addr,
			       sizeof(rts->addr));
	if (nsent < 0) {
		if (errno != EINTR && errno != EAGAIN)
			error(0, errno, "sendto");
		return;
	}

	if ((size_t)nsent < buflen)
		error(0, 0, "sendto: unexpected shortcount");

	if (rts->opts->flood)
		write(1, ".", 1);

	rts->nxmit += 1;
}

static void linger(struct ping_rts *rts, struct icmpmsg *replybuf,
		   size_t buflen)
{
	unsigned secs = MIN(alarm(0), rts->opts->linger);

	struct timeval zero = {
		.tv_sec = 0,
		.tv_usec = 0,
	};
	if (setsockopt(rts->sockfd, SOL_SOCKET, SO_RCVTIMEO, &zero,
		       sizeof(zero))) {
		error(0, errno, "setsockopt");
		return;
	}

	alarm(secs);
	for (;;)
		recv_replies(rts, replybuf, buflen);
}

static void main_loop(struct ping_rts *rts)
{
	const size_t buflen = rts->opts->datalen + sizeof(struct icmphdr);
	struct icmpmsg *replybuf = malloc(buflen); // TODO calloc
	struct icmpmsg *echobuf = malloc(buflen); // TODO calloc
	if (!replybuf || !echobuf)
		error(EXIT_FAILURE, errno, "malloc");

	init_echo(echobuf, buflen, rts->opts->padding);

	uint16_t nseq = 0;

	for (uint16_t i = 0; i < rts->opts->preload; ++i)
		send_echo(rts, echobuf, buflen, nseq++);

	while (!exit_now) {
		struct timeval start;
		gettimeofday_or_err(&start, NULL);

		send_echo(rts, echobuf, buflen, nseq++);
		recv_replies(rts, replybuf, buflen);

		if (nseq >= rts->opts->count)
			break;

		struct timeval now;
		gettimeofday_or_err(&now, NULL);

		time_t diff = now.tv_sec - start.tv_sec;
		if (diff < rts->opts->interval && !exit_now)
			usleep((rts->opts->interval - diff) * 1000000 -
			       (now.tv_usec - start.tv_usec));
	}
	if (!exit_now)
		linger(rts, replybuf, buflen);
	free(replybuf);
	free(echobuf);
}

static double simple_sqrt(double d)
{
	double res = d / 2.0;
	for (int i = 0; i < 100; ++i)
		res = (res + d / res) / 2.0;
	return res;
}

static void print_stats(const struct ping_rts *rts)
{
	printf("--- %s ping statistics ---\n", rts->opts->host);
	printf("%lu packets transmitted, %lu packets received, %.0f%% packet loss\n",
	       rts->nxmit, rts->nrecv,
	       (1.0f - rts->nrecv / rts->nxmit) * 100.0f);

	if (rts->opts->add_time && rts->nrecv) {
		printf("roundtrip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		       rts->min_rtt, rts->avg_rtt, rts->max_rtt,
		       simple_sqrt(rts->var_rtt));
	}
}

static long parse_num_or_err(const char *s, int base, long min, long max)
{
	char *end;
	long res = ft_strtol(s, &end, base);

	if (*end)
		error(EXIT_FAILURE, 0, "invalid value: '%s'", s);
	if (res < min)
		error(EXIT_FAILURE, 0, "value too small: '%s'", s);
	if (res > max)
		error(EXIT_FAILURE, 0, "value too large: '%s'", s);
	return res;
}

static void parse_opts(int argc, char **argv, struct ping_opts *opts)
{
	struct option longopts[] = {
		{ "count", required_argument, NULL, 0 },
		{ "verbose", 0, NULL, 1 },
		{ "flood", 0, NULL, 2 },
		{ "preload", required_argument, NULL, 3 },
		{ "timeout", required_argument, NULL, 4 },
		{ "linger", required_argument, NULL, 5 },
		{ "interval", required_argument, NULL, 6 },
		{ "pattern", required_argument, NULL, 7 },
		{ "size", required_argument, NULL, 8 },
		{ NULL, 0, NULL, 0 },
	};

	int c;
	ft_opterr = 1;
	while ((c = ft_getopt_long(argc, argv, "c:vfl:w:W:i:p:s:", longopts,
				   NULL)) != -1) {
		switch (c) {
		case 'c':
		case 0:
			opts->count =
				parse_num_or_err(ft_optarg, 10, 1, UINT16_MAX);
			break;
		case 'v':
		case 1:
			opts->verbose = true;
			break;
		case 'f':
		case 2:
			opts->flood = true;
			break;
		case 'l':
		case 3:
			opts->preload =
				parse_num_or_err(ft_optarg, 10, 0, UINT16_MAX);
			break;
		case 'w':
		case 4:
			opts->timeout =
				parse_num_or_err(ft_optarg, 10, 1, UINT_MAX);
			break;
		case 'W':
		case 5:
			opts->linger =
				parse_num_or_err(ft_optarg, 10, 1, UINT_MAX);
			break;
		case 'i':
		case 6:
			opts->interval =
				parse_num_or_err(ft_optarg, 10, 1, UINT_MAX);
			break;
		case 'p':
		case 7:
			opts->padding =
				parse_num_or_err(ft_optarg, 16, 0, 0xFF);
			break;
		case 's':
		case 8:
			opts->datalen = parse_num_or_err(ft_optarg, 10, 0,
							 PING_MAX_DATALEN);
			break;
		default:
		case '?':
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (ft_optind >= argc)
		error(EXIT_FAILURE, 0, "destination address required");

	opts->host = argv[ft_optind];
	opts->add_time = opts->datalen >= sizeof(struct timeval);
}

static void get_address(struct ping_rts *rts)
{
	struct addrinfo hints, *res;
	ft_memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_protocol = IPPROTO_ICMP;

	int rc = getaddrinfo(rts->opts->host, NULL, &hints, &res);
	if (rc < 0)
		error(EXIT_FAILURE, 0, "%s: %s", rts->opts->host,
		      gai_strerror(rc));

	assert(res->ai_addrlen == sizeof(rts->addr));
	ft_memcpy(&rts->addr, res->ai_addr, sizeof(rts->addr));

	if (!inet_ntop(AF_INET, &rts->addr.sin_addr, rts->numaddr,
		       sizeof(rts->numaddr)))
		error(EXIT_FAILURE, errno, "inet_ntop");

	freeaddrinfo(res);
}

static void setup_socket(struct ping_rts *rts)
{
	rts->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (rts->sockfd < 0)
		error(EXIT_FAILURE, errno, "socket");

	struct timeval timeout = {
		.tv_sec = rts->opts->interval,
		.tv_usec = 0,
	};
	int yes = 1;
	if (setsockopt(rts->sockfd, SOL_IP, IP_RECVTTL, &yes, sizeof(yes)) ||
	    setsockopt(rts->sockfd, SOL_SOCKET, SO_TIMESTAMP, &yes,
		       sizeof(yes)) ||
	    setsockopt(rts->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)))
		error(EXIT_FAILURE, errno, "setsockopt");
}

static void sighandler(int signum)
{
	(void)signum;
	exit_now = 1;
}

static void setup_sighandlers(void)
{
	struct sigaction act = {
		.sa_handler = sighandler,
	};
	if (sigemptyset(&act.sa_mask))
		error(EXIT_FAILURE, errno, "sigemptyset");
	if (sigaction(SIGINT, &act, NULL) || sigaction(SIGALRM, &act, NULL))
		error(EXIT_FAILURE, errno, "sigaction");
}

static void run_ping(struct ping_rts *rts)
{
	printf("PING %s (%s): %u data bytes\n", rts->opts->host, rts->numaddr,
	       rts->opts->datalen);

	alarm(rts->opts->timeout);

	main_loop(rts);
	print_stats(rts);
}

static void cleanup_rts(struct ping_rts *rts)
{
	if (close(rts->sockfd))
		error(0, errno, "close");
}

int main(int argc, char **argv)
{
	prog_name = argv[0];

	struct ping_opts opts = {
		.host = NULL,
		.datalen = 56,
		.count = UINT_MAX,
		.preload = 0,
		.timeout = 0,
		.linger = 10,
		.interval = 1,
		.padding = 0xff,
		.verbose = false,
		.flood = false,
	};
	parse_opts(argc, argv, &opts);

	struct ping_rts rts = {
		.opts = &opts,
		.nxmit = 0,
		.nrecv = 0,
		.min_rtt = HUGE_VALF,
		.avg_rtt = 0.0,
		.max_rtt = -HUGE_VALF,
		.var_rtt = 0.0,
	};

	get_address(&rts);
	setup_socket(&rts);
	setup_sighandlers();

	run_ping(&rts);

	cleanup_rts(&rts);
	return EXIT_SUCCESS;
}
