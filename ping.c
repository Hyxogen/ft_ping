#include <ft/getopt.h>
#include <ft/stdlib.h>
#include <ft/math.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <limits.h>

struct icmp_echo {
	struct icmphdr header;
	unsigned char data[];
};

struct ping_ctx {
	int sockfd;

	const char *host;

	struct sockaddr_in addr;

	size_t datalen;
	unsigned char padding;
	int add_time;

	int force_numeric;

	char name[256];
	int has_name;

	char addrstr[INET_ADDRSTRLEN];

	unsigned long long ntransmit;
	unsigned long long nreceive;

	int verbose;
	int flood;
	int linger;
	int timeout;
	uint16_t preload;
	uint32_t ping_cnt;

	useconds_t interval;

	float min_rtt;
	float max_rtt;
	float avg_rtt;
	float var_rtt;
};

static const char *program_name = NULL;

static void ping_verror(const char *fmt, va_list ap)
{
	fprintf(stderr, "%s: ", program_name);
	vfprintf(stderr, fmt, ap);
}

__attribute__((format(printf, 1, 2))) static void ping_error(const char *fmt,
							     ...)
{
	va_list ap;
	va_start(ap, fmt);
	ping_verror(fmt, ap);
	va_end(ap);
}

__attribute__((format(printf, 1, 2))) static void
ping_error_and_exit(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	ping_verror(fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void ping_perror(const char *s)
{
	const char *err = strerror(errno);
	if (s)
		ping_error("%s: %s\n", s, err);
	else
		ping_error("%s\n", err);
}

static void ping_perror_and_exit(const char *s)
{
	ping_perror(s);
	exit(EXIT_FAILURE);
}

static long parse_long_or_err(const char *src, int base, long min, long max)
{
	char *end;
	long res = ft_strtol(src, &end, base);
	if (*end)
		ping_error_and_exit("invalid value: '%s'\n", src);
	if (res < min)
		ping_error_and_exit("value too small: '%s'\n", src);
	if (res > max)
		ping_error_and_exit("value too large: '%s'\n", src);
	return res;
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

static ssize_t recv_reply(int sockfd, struct icmp_echo *dest, size_t destlen,
			  int *ttl, void *addr, size_t addrlen,
			  struct timeval *ts)
{
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

	ssize_t nread = recvmsg(sockfd, &msg, 0);
	if (nread < 0) {
		ping_perror("recvmsg");
		return -1;
	}

	if ((size_t)nread < destlen) {
		ping_error("recvmsg: unexpected shortcount\n");
		return -1;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		ping_error("recvmsg: unexpectedly large message\n");
		return -1;
	}

	if (dest->header.type != ICMP_ECHOREPLY) {
		ping_error("received unexpected icmp type\n");
		return -1;
	}
	if (dest->header.code) {
		ping_error("received unexpected icmp reply code\n");
		return -1;
	}

	uint16_t check = inet_checksum(dest, destlen);
	if (check) {
		ping_error("icmp checksum invalid\n");
		return -1;
	}

	assert(ttl);
	*ttl = 0;

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_TTL) {
			memcpy(ttl, CMSG_DATA(cmsg), sizeof(*ttl));
		} else if (cmsg->cmsg_level == SOL_SOCKET &&
			   cmsg->cmsg_type == SCM_TIMESTAMP) {
			memcpy(ts, CMSG_DATA(cmsg), sizeof(*ts));
		}
		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}

	return 0;
}

static int send_echo(const struct ping_ctx *ctx, struct icmp_echo *echo,
		     size_t len, uint16_t seqn)
{
	echo->header.un.echo.sequence = htons(seqn);

	size_t pad_offset = 0;
	if (ctx->add_time) {
		if (gettimeofday((struct timeval *)echo->data, NULL)) {
			ping_perror("gettimeofday");
			return 1;
		}
		pad_offset += sizeof(struct timeval);
	}

	if (pad_offset < ctx->datalen)
		memset(echo->data + pad_offset, ctx->padding,
		       ctx->datalen - pad_offset);

	ssize_t nsent = sendto(ctx->sockfd, echo, len, 0,
			       (const struct sockaddr *)&ctx->addr,
			       sizeof(ctx->addr));
	if (nsent < 0) {
		ping_perror("sendto");
		return 1;
	}

	if ((unsigned long long)nsent < len) {
		ping_error("sendto: unexpected shortcount\n");
		return 1;
	}

	return 0;
}

static float millis_elapsed(struct timeval start, struct timeval end)
{
	return (end.tv_sec - start.tv_sec) * 1000.0f +
	       (end.tv_usec - start.tv_usec) / 1000.0f;
}

static int print_ping(struct ping_ctx *ctx, const struct icmp_echo *reply,
		      int ttl, const struct sockaddr_in *from, float rtt)
{
	char addr[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &from->sin_addr, addr, sizeof(addr))) {
		ping_perror("inet_ntop");
		return EXIT_FAILURE;
	}

	if (!ctx->force_numeric && !ctx->has_name) {
		//TODO NDI format conversion
		if (getnameinfo((const struct sockaddr *)from, sizeof(*from),
				ctx->name, sizeof(ctx->name), NULL, 0, 0))
			ctx->force_numeric = 1;
		else
			ctx->has_name = 1;
	}

	printf("%zu bytes from ", ctx->datalen + sizeof(struct icmphdr));

	int print_name = !ctx->force_numeric && ctx->has_name;

	if (print_name)
		printf("%s (", ctx->name);
	printf("%s", addr);
	if (print_name)
		printf(")");

	printf(": icmp_seq=%hu ttl=%i", ntohs(reply->header.un.echo.sequence),
	       ttl);

	if (ctx->add_time)
		printf(" time=%.3f ms", rtt);
	printf("\n");
	return 0;
}

static float simple_sqrt(float f)
{
	double res = f/2.0;
	for (int i = 0; i < 100; ++i)
		res = (res + f / res) / 2.0;
	return res;
}

//https://en.wikipedia.org/w/index.php?title=Algorithms_for_calculating_variance&oldid=1198125194#Welford's_online_algorithm
static float update_stats(struct ping_ctx *ctx, const struct icmp_echo *reply,
			 const struct timeval *ts)
{
	float rtt = 0.0f;
	if (ctx->add_time) {
		struct timeval sent;
		memcpy(&sent, reply->data, sizeof(sent));
		rtt = millis_elapsed(sent, *ts);

		ctx->min_rtt = ft_fminf(ctx->min_rtt, rtt);
		ctx->max_rtt = ft_fmaxf(ctx->min_rtt, rtt);

		float old_avg = ctx->avg_rtt;

		ctx->avg_rtt = (rtt + ctx->nreceive * ctx->avg_rtt) /
			       (ctx->nreceive + 1);

		if (ctx->nreceive) {
			ctx->var_rtt = ctx->var_rtt +
				       ((rtt - old_avg) * (rtt - ctx->avg_rtt) -
					ctx->var_rtt) /
					       ctx->nreceive;
		} else {
			ctx->var_rtt =
				(rtt - ctx->avg_rtt) * (rtt - ctx->avg_rtt);
		}
	}
	ctx->nreceive += 1;
	return rtt;
}

static void main_loop(struct ping_ctx *ctx)
{
	const size_t len =
		sizeof(struct icmp_echo) + ctx->datalen; //TODO + body size
	struct icmp_echo *reply = malloc(len); //TODO calloc

	uint16_t seqn = -1;
	struct icmp_echo *echo = malloc(len); //TODO calloc
	echo->header.type = ICMP_ECHO;
	echo->header.code = 0;
	echo->header.checksum = 0;
	echo->header.un.echo.id = 0;

	for (;;) {
		++seqn;

		int rc = send_echo(ctx, echo, len, seqn);
		if (rc)
			continue;
		ctx->ntransmit += 1;

		int ttl = 0;
		struct sockaddr_in from;
		struct timeval ts;
		memset(&from, 0, sizeof(from));

		struct timeval before;
		if (gettimeofday(&before, NULL)) {
			ping_perror("gettimeofday");
			continue;
		}

		rc = recv_reply(ctx->sockfd, reply, len, &ttl, &from,
				sizeof(from), &ts);
		if (!rc) {
			float rtt = update_stats(ctx, reply, &ts);
			print_ping(ctx, reply, ttl, &from, rtt);
		}

		if (ctx->ntransmit >= ctx->ping_cnt)
			break;

		struct timeval now;
		if (gettimeofday(&now, NULL)) {
			ping_perror("gettimeofday");
			continue;
		}

		time_t diff = now.tv_sec - before.tv_sec;
		if (diff >= ctx->interval)
			continue;

		useconds_t sleep = (ctx->interval - diff) * 1000000 -
				   (now.tv_usec - before.tv_usec);
		usleep(sleep);
	}
	free(reply);
	free(echo);
}

static void print_stats(const struct ping_ctx *ctx)
{
	printf("--- %s ping statistics ---\n", ctx->host);
	printf("%llu packets transmitted, %llu packets received, %.0f%% packet loss\n",
	       ctx->ntransmit, ctx->nreceive,
	       (1.0f - ctx->nreceive / ctx->ntransmit) * 100.0f);

	if (ctx->add_time && ctx->nreceive) {
		printf("roundtrip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		       ctx->min_rtt, ctx->avg_rtt, ctx->max_rtt,
		       simple_sqrt(ctx->var_rtt));
	}
}

static void parse_options(int argc, char **argv, struct ping_ctx *ctx)
{
	struct option longopts[] = {
		{ "count", required_argument, NULL, 0 },
		{ "verbose", 0, NULL, 1 },
		{ "flood", 0, NULL, 2 },
		{ "preload", required_argument, NULL, 3 },
		{ "timeout", required_argument, NULL, 4 },
		{ "linger", required_argument, NULL, 5 },
		{ "interval", required_argument, NULL, 6 },
		{ NULL, 0, NULL, 0 },
	};

	int c;
	ft_opterr = 1;
	while ((c = ft_getopt_long(argc, argv, "c:vfl:w:W:i:", longopts,
				   NULL)) != -1) {
		switch (c) {
		case 'c':
		case 0:
			ctx->ping_cnt =
				parse_long_or_err(ft_optarg, 10, 0, UINT16_MAX);
			break;
		case 'v':
		case 1:
			ctx->verbose = 1;
			break;
		case 'f':
		case 2:
			ctx->flood = 1;
			break;
		case 'l':
		case 3:
			ctx->preload =
				parse_long_or_err(ft_optarg, 10, 0, LONG_MAX);
			break;
		case 'w':
		case 4:
			ctx->timeout =
				parse_long_or_err(ft_optarg, 10, 0, LONG_MAX);
			break;
		case 'W':
		case 5:
			ctx->linger =
				parse_long_or_err(ft_optarg, 10, 0, INT_MAX);
			break;
		case 'i':
		case 6:
			ctx->interval =
				parse_long_or_err(ft_optarg, 10, 1, INT_MAX);
			break;
		case '?':
			exit(EXIT_FAILURE);
		}
	}
	if (ft_optind >= argc)
		ping_error_and_exit("destination address required\n");
	ctx->host = argv[ft_optind];
}

static void setup_socket(struct ping_ctx *ctx)
{
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_protocol = IPPROTO_ICMP;

	int rc = getaddrinfo(ctx->host, NULL, &hints, &res);
	if (rc < 0)
		ping_error_and_exit("getaddrinfo: %s\n", gai_strerror(rc));
	if (res->ai_addrlen != sizeof(ctx->addr))
		ping_error_and_exit("this should never happen\n");

	memcpy(&ctx->addr, res->ai_addr, sizeof(ctx->addr));
	freeaddrinfo(res);

	ctx->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (ctx->sockfd < 0)
		ping_perror_and_exit("socket");

	struct timeval timeout = {
		.tv_sec = ctx->interval,
		.tv_usec = 0,
	};

	int yes = 1;
	if (setsockopt(ctx->sockfd, SOL_IP, IP_RECVTTL, &yes, sizeof(yes)) ||
	    setsockopt(ctx->sockfd, SOL_SOCKET, SO_TIMESTAMP, &yes,
		       sizeof(yes)) ||
	    setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)))
		ping_perror_and_exit("setsockopt");

	if (!inet_ntop(AF_INET, &ctx->addr.sin_addr, ctx->addrstr,
		       sizeof(ctx->addrstr)))
		ping_perror_and_exit("inet_ntop");
}

#ifndef TEST
int main(int argc, char **argv)
{
	program_name = argv[0];

	struct ping_ctx ctx = {
		.datalen = 56,
		.padding = 0x00,
		.force_numeric = 0,
		.has_name = 0,
		.interval = 1,
		.min_rtt = HUGE_VALF,
		.max_rtt = -HUGE_VALF,
		.ping_cnt = UINT32_MAX,
	};
	parse_options(argc, argv, &ctx);
	ctx.add_time = ctx.datalen > sizeof(struct timeval);

	setup_socket(&ctx);

	printf("PING %s (%s): %zu data bytes\n", ctx.host, ctx.addrstr,
	       ctx.datalen);
	main_loop(&ctx);
	print_stats(&ctx); //TODO actually print stats
	return EXIT_SUCCESS;
}

#else

#define ASSERT_U16_EQUAL_IMPL(a, astr, b, bstr, file, line)                         \
	do {                                                                        \
		if ((uint16_t)(a) != (uint16_t)(b)) {                               \
			fprintf(stderr,                                             \
				"%s:%i: Assertion `%s == %s` failed. %hu != %hu\n", \
				file, line, astr, bstr, a, b);                      \
			abort();                                                    \
		}                                                                   \
	} while (0)

#define ASSERT_U16_EQUAL(a, b) \
	ASSERT_U16_EQUAL_IMPL(a, #a, b, #b, __FILE__, __LINE__)

static void test_inet_checksum()
{
	uint16_t zero = 0;
	assert(inet_checksum(&zero, sizeof(zero)) == 0xffff);

	for (uint32_t i = 0; i < 0x10000; ++i) {
		if (i < 0xFF) {
			ASSERT_U16_EQUAL(inet_checksum(&i, 1), ~(i << 8));
		}
		ASSERT_U16_EQUAL(inet_checksum(&i, 2), ~i);
	}

	uint16_t ab[] = { 0xffff, 0x00ab };
	ASSERT_U16_EQUAL(inet_checksum(ab, sizeof(ab)), ~0x00ab);
}

int main()
{
	test_inet_checksum();
}
#endif
