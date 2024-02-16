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
};

static void error(const char *s)
{
	const char *err = strerror(errno);
	if (s)
		fprintf(stderr, "%s: %s\n", s, err);
	else
		fprintf(stderr, "%s: %s\n", program_name, err);
}

static int do_ping(const struct ping_ctx *ctx)
{
	//printf("%i, %p, %zu, %p, %u\n", ctx->sockfd, &ctx->base, ctx->baselen, addr, len);
	ssize_t nsent = sendto(ctx->sockfd, &ctx->base, ctx->baselen, 0,
			       (const struct sockaddr *)&ctx->addr,
			       sizeof(ctx->addr));
	if (nsent < 0 || nsent < ctx->baselen) {
		error("sendto");
		return 1;
	}
	printf("wrote %li bytes\n", nsent);

	char buf[1024];
	struct iovec iov;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

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
		error("recvmsg");
		return 1;
	}

	fprintf(stdout, "%u bytes\n", (unsigned) nread);
	return 0;
}

// TODO check for overflow
static uint16_t checksum(const void *src, size_t len)
{
	const uint8_t *s = src;

	uint32_t sum = 0;
	size_t i = 0;
	for (; i + 1 < len; i += 2) {
		uint16_t word = ((uint16_t) s[i] << 8) + s[i + 1];
		sum += word;
	}
	if (i < len) {
		assert(0);
		sum += ((uint32_t) s[i] << 8);
	}

	//printf("now: %x\n", sum);
	while (sum & ~0xFFFF) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return (uint16_t) ~sum;
}

int main(int argc, char **argv)
{
	program_name = argv[0];
	if (argc < 2) {
		fprintf(stderr, "%s: destination address required\n", argv[0]);
		return EXIT_SUCCESS;
	}

	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	//hints.ai_family = AF_INET;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_ICMP;

	int rc = getaddrinfo(argv[1], NULL, &hints, &res);
	if (rc < 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		return EXIT_FAILURE;
	}

	struct ping_ctx ctx;
	ctx.sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (ctx.sockfd < 0) {
		error("socket");
		return EXIT_FAILURE;
	}

	ctx.addr = *(struct sockaddr_in*) res->ai_addr;
	ctx.addr.sin_family = AF_INET;
	ctx.addr.sin_port = ((struct sockaddr_in*) res->ai_addr)->sin_port;
	ctx.addr.sin_addr = ((struct sockaddr_in*) res->ai_addr)->sin_addr;

	ctx.base.header.type = ICMP_ECHO;
	ctx.base.header.code = 0;
	ctx.base.header.checksum = 0;
	ctx.base.header.un.echo.id = 1234;
	ctx.base.header.un.echo.sequence = 0;
	ctx.baselen = sizeof(ctx.base);

	ctx.base.header.checksum = checksum(&ctx, ctx.baselen);

	if (do_ping(&ctx))
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
