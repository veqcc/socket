u_int16_t checksum(u_int8_t *data, int len);
u_int16_t checksum2(u_int8_t *data1, int len1, u_int8_t *data2, int len2);
int GetMacAddress(char *device, u_int8_t *hwaddr);
int DummyWait(int ms);
int init_socket(char *device);
