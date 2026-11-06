#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(void) {
  printf("IPPROTO_IP=%d IP_PKTINFO=%d sizeof(in_pktinfo)=%zu offsets=%zu,%zu,%zu\n",IPPROTO_IP,IP_PKTINFO,sizeof(struct in_pktinfo),offsetof(struct in_pktinfo,ipi_ifindex),offsetof(struct in_pktinfo,ipi_spec_dst),offsetof(struct in_pktinfo,ipi_addr));
  printf("IPPROTO_IPV6=%d IPV6_PKTINFO=%d sizeof(in6_pktinfo)=%zu offsets=%zu,%zu\n",IPPROTO_IPV6,IPV6_PKTINFO,sizeof(struct in6_pktinfo),offsetof(struct in6_pktinfo,ipi6_addr),offsetof(struct in6_pktinfo,ipi6_ifindex));
  printf("IPv4: ttl=%d tos=%d recvttl=%d recvtos=%d add=%d drop=%d multicast_if=%d ttl=%d loop=%d multicast_all=%d sizeof(ip_mreq)=%zu\n",IP_TTL,IP_TOS,IP_RECVTTL,IP_RECVTOS,IP_ADD_MEMBERSHIP,IP_DROP_MEMBERSHIP,IP_MULTICAST_IF,IP_MULTICAST_TTL,IP_MULTICAST_LOOP,IP_MULTICAST_ALL,sizeof(struct ip_mreq));
  printf("IPv6: recvpktinfo=%d recvhoplimit=%d recvtclass=%d add=%d drop=%d multicast_if=%d hops=%d loop=%d only=%d sizeof(ipv6_mreq)=%zu\n",IPV6_RECVPKTINFO,IPV6_RECVHOPLIMIT,IPV6_RECVTCLASS,IPV6_ADD_MEMBERSHIP,IPV6_DROP_MEMBERSHIP,IPV6_MULTICAST_IF,IPV6_MULTICAST_HOPS,IPV6_MULTICAST_LOOP,IPV6_V6ONLY,sizeof(struct ipv6_mreq));
}
