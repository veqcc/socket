
int ArpDelTable(struct in_addr *ipaddr);
int ArpSearchTable(struct in_addr *ipaddr, int mac[6]);
int ArpShowTable();
int GetTargetMac(int soc, struct in_addr *daddr, int dmac[6], int gratuitous);
int ArpSend(int soc, int op, int e_smac[6], int e_dmac[6], int smac[6], int dmac[6], int saddr[4], int daddr[4]);
int ArpSendRequestGratuitous(int soc, struct in_addr *targetIp);
int ArpSendRequest(int soc, struct in_addr *targetIp);
int ArpCheckGArp(int soc);
int ArpRecv(int soc, struct ether_header *eh, int *data, int len);