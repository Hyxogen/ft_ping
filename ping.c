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

struct icmp_echo {
	struct icmphdr header;
	unsigned char data[];
};

struct ping_ctx {
	int sockfd;

	struct sockaddr *addr;
	socklen_t addrlen;

	size_t datalen;
	unsigned char padding;
	int add_time;

	int force_numeric;

	char name[256];
	int has_name;

	char addrstr[INET_ADDRSTRLEN];

	useconds_t interval;
};

static const char *program_name = NULL;

__attribute__((format(printf, 1, 2))) static void ping_error(const char *fmt,
							     ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", program_name);
	vfprintf(stderr, fmt, ap);
}

static void ping_perror(const char *s)
{
	const char *err = strerror(errno);
	if (s)
		ping_error("%s: %s\n", s, err);
	else
		ping_error("%s\n", err);
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
		sum += (uint16_t) * (uint8_t *)s << 8;

	while (sum & ~0xFFFF) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
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

	ssize_t nsent =
		sendto(ctx->sockfd, echo, len, 0, ctx->addr, ctx->addrlen);
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

static int print_ping(struct ping_ctx *ctx, const struct icmp_echo *reply,
		      int ttl, const struct sockaddr_in *from,
		      const struct timeval *ts)
{
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
	printf("%s", ctx->addrstr);
	if (print_name)
		printf(")");

	printf(": icmp_seq=%hu ttl=%i", ntohs(reply->header.un.echo.sequence),
	       ttl);

	if (ctx->add_time) {
		struct timeval *sent = (struct timeval *)reply->data;
		float ms = (ts->tv_sec - sent->tv_sec) * 1000.0f +
			   (ts->tv_usec - sent->tv_usec) / 1000.0f;
		printf(" time=%.3f ms", ms);
	}
	printf("\n");
	return 0;
}

static void main_loop(struct ping_ctx *ctx)
{
	const size_t buflen =
		sizeof(struct icmp_echo) + ctx->datalen; //TODO + body size
	struct icmp_echo *buf = malloc(buflen); //TODO calloc

	uint16_t seqn = -1;
	struct icmp_echo *echo = malloc(buflen); //TODO calloc
	echo->header.type = ICMP_ECHO;
	echo->header.code = 0;
	echo->header.checksum = 0;
	echo->header.un.echo.id = 0;

	for (;;) {
		++seqn;

		int rc = send_echo(ctx, echo, buflen, seqn);
		if (rc)
			continue;

		int ttl = 0;
		struct sockaddr_in from;
		struct timeval ts;
		memset(&from, 0, sizeof(from));

		rc = recv_reply(ctx->sockfd, buf, buflen, &ttl, &from,
				sizeof(from), &ts);
		if (rc)
			continue;

		print_ping(ctx, buf, ttl, &from, &ts);

		usleep(ctx->interval * 1000);
	}
	free(buf);
	free(echo);
}

#ifndef TEST
int main(int argc, char **argv)
{
	program_name = argv[0];
	if (argc < 2) {
		ping_error("destination address required\n");
		return EXIT_SUCCESS;
	}

	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_protocol = IPPROTO_ICMP;

	int rc = getaddrinfo(argv[1], NULL, &hints, &res);
	if (rc < 0) {
		ping_error("getaddrinfo: %s\n", gai_strerror(rc));
		return EXIT_FAILURE;
	}

	struct ping_ctx ctx;
	ctx.sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (ctx.sockfd < 0) {
		ping_perror("socket");
		return EXIT_FAILURE;
	}

	ctx.addr = res->ai_addr;
	ctx.addrlen = res->ai_addrlen;
	ctx.datalen = 56;
	ctx.padding = 0x00;
	ctx.force_numeric = 0;
	ctx.has_name = 0;

	ctx.interval = 1000;

	int yes = 1;
	if (setsockopt(ctx.sockfd, SOL_IP, IP_RECVTTL, &yes, sizeof(yes)) ||
	    setsockopt(ctx.sockfd, SOL_SOCKET, SO_TIMESTAMP, &yes,
		       sizeof(yes))) {
		ping_perror("setsockopt");
		return EXIT_FAILURE;
	}

	ctx.add_time = ctx.datalen > sizeof(struct timeval);

	if (!inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
		       ctx.addrstr, sizeof(ctx.addrstr))) {
		ping_perror("inet_ntop");
		return EXIT_FAILURE;
	}

	printf("PING %s (%s): %zu data bytes\n", argv[1], ctx.addrstr, ctx.datalen);
	main_loop(&ctx);
	freeaddrinfo(res);
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
