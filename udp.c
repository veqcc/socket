#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/ioctl.h>
#include	<netpacket/packet.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/if_ether.h>
#include	<netinet/udp.h>
#include	<linux/if.h>
#include	<arpa/inet.h>
#include	<pthread.h>
#include	"sock.h"
#include	"ether.h"
#include	"ip.h"
#include	"icmp.h"
#include	"dhcp.h"
#include	"udp.h"
#include	"param.h"

extern PARAM Param;

// IP擬似ヘッダ
struct pseudo_ip {
    struct in_addr ip_src;
    struct in_addr ip_dst;
    u_int8_t dummy;
    u_int8_t ip_p;
    u_int16_t ip_len;
};

#define	UDP_TABLE_NO (16)

typedef struct {
    u_int16_t port;
} UDP_TABLE;

UDP_TABLE UdpTable[UDP_TABLE_NO];
pthread_rwlock_t UdpTableLock=PTHREAD_RWLOCK_INITIALIZER;


int print_udp(struct udphdr *udp) {
    printf("udp-----------------------------------------------------------------------------\n");

    printf("source=%d\n", ntohs(udp->source));
    printf("dest=%d\n", ntohs(udp->dest));
    printf("len=%d\n", ntohs(udp->len));
    printf("check=%04x\n", ntohs(udp->check));

    return (0);
}

u_int16_t UdpChecksum(struct in_addr *saddr,struct in_addr *daddr,u_int8_t proto,u_int8_t *data,int len) {
    struct pseudo_ip p_ip;
    u_int16_t sum;

    memset(&p_ip, 0, sizeof(struct pseudo_ip));
    p_ip.ip_src.s_addr = saddr->s_addr;
    p_ip.ip_dst.s_addr = daddr->s_addr;
    p_ip.ip_p = proto;
    p_ip.ip_len = htons(len);

    sum = checksum2((u_int8_t * ) & p_ip, sizeof(struct pseudo_ip), data, len);
    if (sum == 0x0000) {
        sum = 0xFFFF;
    }
    return (sum);
}

int UdpAddTable(u_int16_t port) {
    int i, freeNo;

    pthread_rwlock_wrlock(&UdpTableLock);

    freeNo = -1;
    for (i = 0; i < UDP_TABLE_NO; i++) {
        if (UdpTable[i].port == port) {
            printf("UdpAddTable:port %d:already exist\n", port);
            pthread_rwlock_unlock(&UdpTableLock);
            return (-1);
        } else if (UdpTable[i].port == 0) {
            if (freeNo == -1) {
                freeNo = i;
            }
        }
    }
    if (freeNo == -1) {
        printf("UdpAddTable:no free table\n");
        pthread_rwlock_unlock(&UdpTableLock);
        return (-1);
    }
    UdpTable[freeNo].port = port;

    pthread_rwlock_unlock(&UdpTableLock);

    return (freeNo);
}

int UdpSearchTable(u_int16_t port) {
    int i;

    pthread_rwlock_rdlock(&UdpTableLock);

    for (i = 0; i < UDP_TABLE_NO; i++) {
        if (UdpTable[i].port == port) {
            pthread_rwlock_unlock(&UdpTableLock);
            return (i);
        }
    }

    pthread_rwlock_unlock(&UdpTableLock);

    return (-1);
}

int UdpShowTable() {
    int i;

    pthread_rwlock_rdlock(&UdpTableLock);

    for (i = 0; i < UDP_TABLE_NO; i++) {
        if (UdpTable[i].port != 0) {
            printf("UDP:%d:%u\n", i, UdpTable[i].port);
        }
    }

    pthread_rwlock_unlock(&UdpTableLock);

    return (0);
}

u_int16_t UdpSearchFreePort() {
    u_int16_t i;

    for (i = 32768; i < 61000; i++) {
        if (UdpSearchTable(i) == -1) {
            return (i);
        }
    }

    return (0);
}

int UdpSocket(u_int16_t port) {
    int no;

    if (port == DHCP_CLIENT_PORT) {
        printf("UdpSocket:port %d:cannot use\n", port);
        return (-1);
    }
    if (port == 0) {
        if ((port = UdpSearchFreePort()) == 0) {
            printf("UdpSocket:no free port\n");
            return (-1);
        }
    }
    no = UdpAddTable(port);
    if (no == -1) {
        return (-1);
    }
    return (no);
}

int UdpSocketClose(u_int16_t port) {
    int no;

    no = UdpSearchTable(port);
    if (no == -1) {
        printf("UdpSocketClose:%u:not exists\n", port);
        return (-1);
    }
    pthread_rwlock_wrlock(&UdpTableLock);
    UdpTable[no].port = 0;
    pthread_rwlock_unlock(&UdpTableLock);

    return (0);
}

// DUPパケットをMACアドレス指定で送信する関数
int UdpSendLink(int soc,u_int8_t smac[6],u_int8_t dmac[6],struct in_addr *saddr,struct in_addr *daddr,u_int16_t sport,u_int16_t dport,int dontFlagment,u_int8_t *data,int len) {
    u_int8_t *ptr, sbuf[64 * 1024];
    struct udphdr *udp;

    ptr = sbuf;
    udp = (struct udphdr *) ptr;
    memset(udp, 0, sizeof(struct udphdr));
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(sizeof(struct udphdr) + len);
    udp->check = 0;
    ptr += sizeof(struct udphdr);

    memcpy(ptr, data, len);
    ptr += len;
    udp->check = UdpChecksum(saddr, daddr, IPPROTO_UDP, sbuf, ptr - sbuf);

    printf("=== UDP ===[\n");
    IpSendLink(soc, smac, dmac, saddr, daddr, IPPROTO_UDP, dontFlagment, Param.IpTTL, sbuf, ptr - sbuf);
    print_udp(udp);
    print_hex(data, len);
    printf("]\n");

    return (0);
}

// UODパケットの送信。MACアドレスの解決はIpSend()にて。
int UdpSend(int soc,struct in_addr *saddr,struct in_addr *daddr,u_int16_t sport,u_int16_t dport,int dontFlagment,u_int8_t *data,int len) {
    u_int8_t *ptr, sbuf[64 * 1024];
    struct udphdr *udp;

    ptr = sbuf;
    udp = (struct udphdr *) ptr;
    memset(udp, 0, sizeof(struct udphdr));
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(sizeof(struct udphdr) + len);
    udp->check = 0;
    ptr += sizeof(struct udphdr);

    memcpy(ptr, data, len);
    ptr += len;
    udp->check = UdpChecksum(saddr, daddr, IPPROTO_UDP, sbuf, ptr - sbuf);

    printf("=== UDP ===[\n");
    IpSend(soc, saddr, daddr, IPPROTO_UDP, dontFlagment, Param.IpTTL, sbuf, ptr - sbuf);
    print_udp(udp);
    print_hex(data, len);
    printf("]\n");

    return (0);
}

int UdpRecv(int soc,struct ether_header *eh,struct ip *ip,u_int8_t *data,int len) {
    struct udphdr *udp;
    u_int8_t *ptr = data;
    u_int16_t sum;
    int udplen;

    udplen = len;

    sum = UdpChecksum(&ip->ip_src, &ip->ip_dst, ip->ip_p, data, udplen);
    if (sum != 0 && sum != 0xFFFF) {
        printf("UdpRecv:bad udp checksum(%x):udplen=%u\n", sum, udplen);
        return (-1);
    }

    udp = (struct udphdr *) ptr;
    ptr += sizeof(struct udphdr);
    udplen -= sizeof(struct udphdr);

    if (ntohs(udp->dest) == DHCP_CLIENT_PORT) {
        DhcpRecv(soc, ptr, udplen, eh, ip, udp);
    } else {
        if (UdpSearchTable(ntohs(udp->dest)) != -1) {
            printf("--- recv ---[\n");
            print_ether_header(eh);
            print_ip(ip);
            print_udp(udp);
            print_hex(ptr, udplen);
            printf("]\n");
        } else {
            IcmpSendDestinationUnreachable(soc, &ip->ip_src, ip, data, len);
        }
    }

    return (0);
}