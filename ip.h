
void print_ip(struct ip *ip);
void IpRecvBufInit();
int IpRecv(int soc, int *raw, int raw_len, struct ether_header *eh, int *data, int len);
int IpSend(int soc, struct in_addr *saddr, struct in_addr *daddr,
        int proto, int dontFlagment, int ttl, int *data, int len);