void print_ip(struct ip *ip);
int IpRecvBufInit();
int IpRecvBufAdd(u_int16_t id);
int IpRecvBufDel(u_int16_t id);
int IpRecvBufSearch(u_int16_t id);
int IpRecv(int soc,u_int8_t *raw,int raw_len,struct ether_header *eh,u_int8_t *data,int len);
int IpSendLink(int soc,u_int8_t smac[6],u_int8_t dmac[6],struct in_addr *saddr,struct in_addr *daddr,u_int8_t proto,int dontFlagment,int ttl,u_int8_t *data,int len);
int IpSend(int soc,struct in_addr *saddr,struct in_addr *daddr,u_int8_t proto,int dontFlagment,int ttl,u_int8_t *data,int len);