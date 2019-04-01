#include	<stdio.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<limits.h>
#include	<time.h>
#include	<sys/ioctl.h>
#include	<netpacket/packet.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/if_ether.h>
#include	<linux/if.h>
#include	<arpa/inet.h>
#include	"sock.h"
#include	"ether.h"
#include	"arp.h"
#include	"ip.h"
#include	"icmp.h"
#include	"param.h"

extern PARAM Param;

u_int8_t AllZeroMac[6]={0,0,0,0,0,0};
u_int8_t BcastMac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

char *my_ether_ntoa_r(u_int8_t *hwaddr,char *buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return (buf);
}

int my_ether_aton(char *str,u_int8_t *mac) {
    char *ptr, *saveptr = NULL;
    int c;
    char *tmp = strdup(str);

    for (c = 0, ptr = strtok_r(tmp, ":", &saveptr); c < 6; c++, ptr = strtok_r(NULL, ":", &saveptr)) {
        if (ptr == NULL) {
            free(tmp);
            return (-1);
        }
        mac[c] = strtol(ptr, NULL, 16);
    }
    free(tmp);

    return (0);
}

int print_hex(u_int8_t *data,int size) {
    int i, j;

    for (i = 0; i < size;) {
        for (j = 0; j < 16; j++) {
            if (j != 0) {
                printf(" ");
            }
            if (i + j < size) {
                printf("%02X", *(data + j));
            } else {
                printf("  ");
            }
        }
        printf("    ");
        for (j = 0; j < 16; j++) {
            if (i < size) {
                if (isascii(*data) && isprint(*data)) {
                    printf("%c", *data);
                } else {
                    printf(".");
                }
                data++;
                i++;
            } else {
                printf(" ");
            }
        }
        printf("\n");
    }

    return (0);
}

void print_ether_header(struct ether_header *eh) {
    char buf1[80];

    printf("---ether_header---\n");

    printf("ether_dhost=%s\n", my_ether_ntoa_r(eh->ether_dhost, buf1));

    printf("ether_shost=%s\n", my_ether_ntoa_r(eh->ether_shost, buf1));

    printf("ether_type=%02X", ntohs(eh->ether_type));
    switch (ntohs(eh->ether_type)) {
        case ETHERTYPE_PUP:
            printf("(Xerox PUP)\n");
            break;
        case ETHERTYPE_IP:
            printf("(IP)\n");
            break;
        case ETHERTYPE_ARP:
            printf("(Address resolution)\n");
            break;
        case ETHERTYPE_REVARP:
            printf("(Reverse ARP)\n");
            break;
        default:
            printf("(unknown)\n");
            break;
    }

    return;
}

int EtherSend(int soc,u_int8_t smac[6],u_int8_t dmac[6],u_int16_t type,u_int8_t *data,int len) {
    struct ether_header *eh;
    u_int8_t *ptr, sbuf[sizeof(struct ether_header) + ETHERMTU];
    int padlen;

    if (len > ETHERMTU) {
        printf("EtherSend:data too long:%d\n", len);
        return (-1);
    }

    ptr = sbuf;
    eh = (struct ether_header *) ptr;
    memset(eh, 0, sizeof(struct ether_header));
    memcpy(eh->ether_dhost, dmac, 6);
    memcpy(eh->ether_shost, smac, 6);
    eh->ether_type = htons(type);
    ptr += sizeof(struct ether_header);

    memcpy(ptr, data, len);
    ptr += len;

    if ((ptr - sbuf) < ETH_ZLEN) {
        padlen = ETH_ZLEN - (ptr - sbuf);
        memset(ptr, 0, padlen);
        ptr += padlen;
    }

    write(soc, sbuf, ptr - sbuf);
    print_ether_header(eh);

    return (0);
}

int EtherRecv(int soc,u_int8_t *in_ptr,int in_len) {
    struct ether_header *eh;
    u_int8_t *ptr = in_ptr;
    int len = in_len;

    eh = (struct ether_header *) ptr;
    ptr += sizeof(struct ether_header);
    len -= sizeof(struct ether_header);

    if (memcmp(eh->ether_dhost, BcastMac, 6) != 0 && memcmp(eh->ether_dhost, Param.vmac, 6) != 0) {
        return (-1);
    }

    if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
        ArpRecv(soc, eh, ptr, len);
    } else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
        IpRecv(soc, in_ptr, in_len, eh, ptr, len);
    }

    return (0);
}