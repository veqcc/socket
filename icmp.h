
int PingSend(int soc, struct in_addr *daddr, int size);
int IcmpRecv(int soc, int *raw, int raw_len, struct ether_header *eh, struct ip *ip, int *data, int len);