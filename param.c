
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "ether.h"
#include "param.h"

extern PARAM Param;

void SetDefaultParam() {
    Param.MTU = DEFAULT_MTU;
    Param.IpTTL = DEFAULT_IP_TTL;
}

int ReadParam(char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("%s cannot read\n", filename);
        return -1;
    }

    char buf[1024];
    char *ptr, *save_ptr;

    while (1) {
        fgets(buf, sizeof(buf), fp);
        if (feof(fp)) {
            break;
        }
        ptr = strtok_r(buf, "=", &save_ptr);
        if (ptr != NULL) {
            if (strcmp(ptr, "IP-TTL") == 0) {
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
                if (ptr != NULL) {
                    Param.IpTTL = atoi(ptr);
                }
            } else if (strcmp(ptr, "MTU") == 0) {
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
                if (ptr != NULL) {
                    Param.MTU = atoi(ptr);
                    if (Param.MTU > ETHERMTU) {
                        printf("ReadParam:MTU(%d) <= ETHERMTU(%d)", Param.MTU, ETHERMTU);
                        Param.MTU = ETHERMTU;
                    }
                }
            } else if (strcmp(ptr, "gateway") == 0) {
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
                if (ptr != NULL) {
                    Param.gateway.s_addr = inet_addr(ptr);
                }
            } else if (strcmp(ptr, "device") == 0) {
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
                if (ptr != NULL) {
                    Param.device = strdup(ptr);
                }
            } else if (strcmp(ptr, "vmac") == 0) {
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
                if (ptr != NULL) {
                    my_ether_aton(ptr, Param.vmac);
                }
            } else if (strcmp(ptr, "vip") == 0) {
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
                if (ptr != NULL) {
                    Param.vip.s_addr = inet_addr(ptr);
                }
            } else if (strcmp(ptr, "vmask") == 0) {
                ptr = strtok_r(NULL, "\r\n", &save_ptr);
                if (ptr != NULL) {
                    Param.vmask.s_addr = inet_addr(ptr);
                }
            }
        }
    }

    fclose(fp);
    return 0;
}

int isTargetIPAddr(struct in_addr *addr) {
    if (Param.vip.s_addr == addr->s_addr) {
        return 1;
    }

    return 0;
}

int isSameSubnet(struct in_addr *addr) {
    if ((addr->s_addr & Param.vmask.s_addr) == (Param.vip.s_addr)) {
        return 1;
    } else {
        return 0;
    }
}
