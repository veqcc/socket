
char *my_ether_ntoa_r(int *hwaddr, char *buf);
int my_ether_aton(char *str, int *mac);
int EtherSend(int soc, int smac[6], int dmac[6], int type, int *data, int len);
int EtherRecv(int soc, int *in_ptr, int in_len);