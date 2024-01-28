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
  printf("trying to write to %i\n", fd);
  int rc = sendto(fd, data, n, 0, addr, len);
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
  hints.ai_socktype = SOCK_DGRAM;
  //hints.ai_socktype = SOCK_RAW;
  //hints.ai_protocol = IPPROTO_ICMP;

  int rc = getaddrinfo("127.0.0.1", NULL, &hints, &res);
  if (rc) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
    abort();
  }
  
  //int sockfd = -1;
  int sockfd = socket(AF_INET, SOCK_DGRAM, getprotobyname("icmp")->p_proto);
  if (sockfd < 0) {
    perror("socket");
    abort();
  }

  /*while (res) {
    printf("trying\n");
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
      res = res->ai_next;
      continue;
    }
    rc = connect(sockfd, res->ai_addr, res->ai_addrlen);
    if (rc == -1) {
      close(sockfd);
      res = res->ai_next;
      continue;
    }
    break;
  }
  if (!res) {
    perror("failed to connect");
    abort();
  }*/

  printf("fd: %i\n", sockfd);
  struct icmphdr hdr;
  memset(&hdr, 0, sizeof hdr);
  hdr.type = ICMP_ECHO;
  hdr.un.echo.id = 1234;
  rwrite(sockfd, &hdr, sizeof hdr, res->ai_addr, res->ai_protocol);

  /*abort();
  uint8_t type = 8;
  rwrite(sockfd, &type, sizeof(type), res->ai_addr, res->ai_protocol);
  uint8_t code = 0;
  rwrite(sockfd, &code, sizeof(code), res->ai_addr, res->ai_protocol);
  uint16_t checksum = htons(~((uint16_t) 8));
  rwrite(sockfd, &checksum, sizeof(checksum), res->ai_addr, res->ai_protocol);
  uint32_t ident_seq = 0;
  rwrite(sockfd, &ident_seq, sizeof(checksum), res->ai_addr, res->ai_protocol);
  fsync(sockfd);
  printf("written echo\n");*/

  struct icmp_header header;
  memset(&header, 0, sizeof header);
  ssize_t nread = read(sockfd, &header, sizeof header);
  if (nread < 0) {
    perror("read");
    abort();
  }

  printf("read %i bytes\n", nread);
}
