int print_icmp(struct icmp *icmp);
int IcmpSendEchoReply(int soc,struct ip *r_ip,struct icmp *r_icmp,u_int8_t *data,int len,int ip_ttl);
int IcmpSendEcho(int soc,struct in_addr *daddr,int seqNo,int size);
int IcmpSendDestinationUnreachable(int soc,struct in_addr *daddr,struct ip *ip,u_int8_t *data,int len);
int PingSend(int soc,struct in_addr *daddr,int size);
int IcmpRecv(int soc,u_int8_t *raw,int raw_len,struct ether_header *eh,struct ip *ip,u_int8_t *data,int len);
int PingCheckReply(struct ip *ip,struct icmp *icmp);