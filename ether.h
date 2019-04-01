char *my_ether_ntoa_r(u_int8_t *hwaddr,char *buf);
int my_ether_aton(char *str,u_int8_t *mac);
int print_hex(u_int8_t *data,int size);
void print_ether_header(struct ether_header *eh);
int EtherSend(int soc,u_int8_t smac[6],u_int8_t dmac[6],u_int16_t type,u_int8_t *data,int len);
int EtherRecv(int soc,u_int8_t *in_ptr,int in_len);