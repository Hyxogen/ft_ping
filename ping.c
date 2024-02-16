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

static const char *program_name = NULL;

struct icmp_echo {
	struct icmphdr header;
	unsigned char data[];
};

struct ping_ctx {
	int sockfd;
	struct sockaddr_in addr;
	struct icmp_echo base;
	size_t baselen;
	useconds_t interval;
};

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

static int do_ping(const struct ping_ctx *ctx)
{
	ssize_t nsent = sendto(ctx->sockfd, &ctx->base, ctx->baselen, 0,
			       (const struct sockaddr *)&ctx->addr,
			       sizeof(ctx->addr));
	if (nsent < 0) {
		ping_perror("sendto");
		return 1;
	}
	if ((unsigned long long)nsent < ctx->baselen) {
		ping_error("sendto: unexpeced shortcount\n");
		return 1;
	}

	struct icmp_echo *resp = malloc(sizeof(resp) + 128);
	struct iovec iov;
	iov.iov_base = resp;
	iov.iov_len = sizeof(resp) + 128;
	memset(resp, 0, iov.iov_len);

	char name[128];
	char cbuf[512];
	struct msghdr msg;

	msg.msg_name = name;
	msg.msg_namelen = sizeof(name);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	msg.msg_flags = 0;

	ssize_t nread = recvmsg(ctx->sockfd, &msg, 0);
	if (nread < 0) {
		ping_perror("recvmsg");
		return 1;
	}

	char from[1024];
	const char *tmp =
		inet_ntop(AF_INET, &ctx->addr.sin_addr, from, sizeof(from));
	if (!tmp) {
		ping_perror("inet_ntop");
		return 1;
	}

	if (resp->header.type != ICMP_ECHOREPLY) {
		fprintf(stderr, "not an echo reply, %hhu\n", resp->header.type);
	}

	uint16_t ch = inet_checksum(resp, nread);

	if (ch) {
		uint16_t *s = (uint16_t *)resp;
		for (int i = 0; i < nread; i += 2) {
			printf("%04hx ", s[i]);
		}
		printf("\n");
		fprintf(stderr,
			"invalid checksum, packet said: %hx, we got %hx\n",
			resp->header.checksum, ch);
	}

	fprintf(stdout, "%u bytes from %s \n", (unsigned)nread, tmp);
	return 0;
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
	//hints.ai_family = AF_INET;
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

	ctx.base.header.type = ICMP_ECHO;
	ctx.base.header.code = 0;
	ctx.base.header.checksum = 0;
	ctx.base.header.un.echo.id = 1234;
	ctx.base.header.un.echo.sequence = 0;
	ctx.baselen = sizeof(ctx.base);

	ctx.base.header.checksum = inet_checksum(&ctx, ctx.baselen);

	ctx.interval = 1000;

	for (;;) {
		do_ping(&ctx);
		usleep(ctx.interval * 1000);
	}
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
