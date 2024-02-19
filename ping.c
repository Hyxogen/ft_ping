#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdarg.h>

#define MAX_BODY_SIZE 128

struct icmp_echo {
	struct icmphdr header;
	unsigned char data[];
};

struct ping_ctx {
	int sockfd;
	struct sockaddr_in addr;
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

static ssize_t recv_reply(int sockfd, struct icmp_echo *dest, size_t destlen, int *ttl, void *addr, size_t addrlen)
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
	*ttl = 0; //TODO set

	return 0;
}

static int send_echo(const struct ping_ctx *ctx, const struct icmp_echo *echo, size_t len)
{
	ssize_t nsent = sendto(ctx->sockfd, echo, len, 0,
			       (const struct sockaddr *)&ctx->addr,
			       sizeof(ctx->addr));
	if (nsent < 0) {
		ping_perror("sendto");
		return 1;
	}

	if ((unsigned long long) nsent < len) {
		ping_error("sendto: unexpected shortcount\n");
		return 1;
	}

	return 0;
}

static void main_loop(struct ping_ctx *ctx)
{
	const size_t buflen = sizeof(struct icmp_echo); //TODO + body size
	struct icmp_echo *buf = malloc(buflen); //TODO calloc

	uint16_t seqn = 0;
	struct icmp_echo *echo = malloc(buflen); //TODO calloc
	echo->header.type = ICMP_ECHO;
	echo->header.code = 0;
	echo->header.checksum = 0;
	echo->header.un.echo.id = 0;

	for (;;) {
		echo->header.un.echo.sequence = htons(seqn);

		int rc = send_echo(ctx, echo, buflen);

		if (rc)
			continue;

		int ttl = 0;

		struct sockaddr_in from;
		memset(&from, 0, sizeof(from));

		rc = recv_reply(ctx->sockfd, buf, buflen, &ttl, &from, sizeof(from));
		if (rc)
			continue;

		char addr[INET_ADDRSTRLEN];
		if (!inet_ntop(AF_INET, &from.sin_addr, addr, sizeof(addr))) {
			ping_perror("inet_ntop");
			continue;
		}

		fprintf(stdout,
			"%zu bytes from %s: icmp_seq=%hu ttl=%i time=%llu ms\n",
			buflen, addr, seqn, ttl, 0llu);
		usleep(ctx->interval * 1000);
		++seqn;
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
	hints.ai_family = AF_UNSPEC;
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

	ctx.addr = *(struct sockaddr_in *)res->ai_addr;
	ctx.addr.sin_family = AF_INET;
	ctx.addr.sin_port = ((struct sockaddr_in *)res->ai_addr)->sin_port;
	ctx.addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

	ctx.interval = 1000;

	main_loop(&ctx);
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
