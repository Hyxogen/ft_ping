#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>

struct icmp_header {
  uint8_t type;
  uint8_t code;
  uint16_t check;
  uint32_t rem;
};

void rwrite(int fd, const void *data, size_t n, struct sockaddr *addr, socklen_t len)
{
  printf("trying to write %zu bytes to fd %i, socklen: %zu\n", n, fd, len);
  int rc = sendto(fd, data, n, 0, addr, len);
  //int rc = write(fd, data, n);
  if (rc < 0) {
    perror("write");
    abort();
  }
  printf("wrote something\n");
}

int main(int argc, char **argv)
{
  struct addrinfo hints, *res;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  //hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_ICMP;
  //hints.ai_socktype = SOCK_RAW;
  //hints.ai_protocol = getprotobyname("icmp")->p_proto;

  int rc = getaddrinfo("127.0.0.1", NULL, &hints, &res);
  if (rc) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
    abort();
  }
  
  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

  printf("fd: %i\n", sockfd);
  struct icmphdr hdr;
  memset(&hdr, 0, sizeof hdr);
  hdr.type = ICMP_ECHO;
  hdr.un.echo.id = 1234;
  hdr.checksum = htons(~((uint16_t) 8));
  rwrite(sockfd, &hdr, sizeof hdr, res->ai_addr, res->ai_addrlen);

  /*char buffer[1024];
  memset(buffer, 0, sizeof(buffer));

  ssize_t nread = read(sockfd, &buffer, sizeof buffer);
  if (nread < 0) {
          perror("read");
          abort();
  }
  printf("read %i bytes\n", nread);

  for (ssize_t i = 0; i < nread; ++i) {
          printf("%02hhx ", (unsigned char)buffer[i]);
  }
  printf("\n");*/

  char buffer[1024];
  struct iovec data;
  struct msghdr msg;
  memset(&msg, 0, sizeof msg);
  data.iov_base = buffer;
  data.iov_len = sizeof buffer;
  msg.msg_iov = &data;
  msg.msg_iovlen = 1;

  ssize_t nread = recvmsg(sockfd, &msg, 0);
  if (nread < 0) {
          perror("read");
          abort();
  }
  printf("read %i bytes\n", nread);

  for (ssize_t i = 0; i < nread; ++i) {
          printf("%02hhx ", (unsigned char)buffer[i]);
  }
  printf("\n");
}
