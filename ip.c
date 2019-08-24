
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

#include "arp.h"
#include "param.h"
#include "sock.h"
#include "ether.h"
#include "icmp.h"

#define IP_RECV_BUF_NO 16

extern PARAM Param;

typedef struct {
    time_t timestamp;
    int id;
    int data[64 * 1024];
    int len;
} IP_RECV_BUF;

IP_RECV_BUF IpRecvBuf[IP_RECV_BUF_NO];

void print_ip(struct ip *ip) {
    static char *proto[] = {
            "undefined",
            "ICMP",
            "IGMP",
            "undefined",
            "IPIP",
            "undefined",
            "TCP",
            "undefined",
            "EGP",
            "undefined",
            "undefined",
            "undefined",
            "PUP",
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "UDP"
    };

    char buf[80];
    printf("ip------------------------------------------------------------\n");
    printf("ip_v   = %u\n", ip->ip_v);
    printf("ip_hl  = %u\n", ip->ip_hl);
    printf("ip_tos = %x\n", ip->ip_tos);
    printf("ip_len = %d\n", ntohs(ip->ip_len));
    printf("ip_id  = %u\n", ntohs(ip->ip_id));
    printf("ip_off = %x, %d\n", (ntohs(ip->ip_off)) >> 13 & 0x07, ntohs(ip->ip_off) & IP_OFFMASK);
    printf("ip_ttl = %u\n", ip->ip_ttl);
    printf("ip_p   = %u", ip->ip_p);
    if (ip->ip_p <= 17) {
        printf("(%s)\n", proto[ip->ip_p]);
    } else {
        printf("(undefined)\n");
    }
    printf("ip_sum = %04x\n", ntohs(ip->ip_sum));
    printf("ip_src = %s\n", inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf)));
    printf("ip_dst = %s\n", inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf)));
}

void IpRecvBufInit() {
    for (int i = 0; i < IP_RECV_BUF_NO; i++) {
        IpRecvBuf[i].id = -1;
    }
}

int IpRecvBufAdd(int id) {
    int freeNo = -1;
    time_t oldestTime = INTMAX_MAX;
    int oldestNo = -1;
    for (int i = 0; i < IP_RECV_BUF_NO; i++) {
        if (IpRecvBuf[i].id == -1) {
            freeNo = i;
        } else {
            // 指定したidと同じバッファがあればそれを返す
            if (IpRecvBuf[i].id == id) {
                return i;
            }

            // 空きがない場合、timestampがもっとも古いものを置き換える
            if (IpRecvBuf[i].timestamp < oldestTime) {
                oldestTime = IpRecvBuf[i].timestamp;
                oldestNo = i;
            }
        }
    }

    if (freeNo == -1) {
        freeNo = oldestNo;
    }

    IpRecvBuf[freeNo].timestamp = time(NULL);
    IpRecvBuf[freeNo].id = id;
    IpRecvBuf[freeNo].len = 0;

    return freeNo;
}

int IpRecvBufDel(int id) {
    for (int i = 0; i < IP_RECV_BUF_NO; i++) {
        if (IpRecvBuf[i].id == id) {
            IpRecvBuf[i].id = -1;
            return 1;
        }
    }

    return 0;
}

int IpRecv(int soc, int *raw, int raw_len, struct ether_header *eh, int *data, int len) {
    if (len < sizeof(struct ip)) {
        printf("len(%d) < sizeof(struct ip)\n", len);
        return -1;
    }

    // IPパケットデータを、ip構造体にキャストして内容を確認
    int *ptr = data;
    struct ip *ip = (struct ip *) ptr;
    ptr += sizeof(struct ip);
    len -= sizeof(struct ip);

    int option[1500];
    int optionLen = ip->ip_hl * 4 - sizeof(struct ip);
    if (optionLen > 0) {
        if (optionLen >= 1500) {
            printf("IP optionLen(%d) too big\n", optionLen);
            return -1;
        }
        memcpy(option, ptr, optionLen);
        ptr += optionLen;
        len -= optionLen;
    }

    int sum;
    if (optionLen == 0) {
        sum = checksum((int *)ip, sizeof(struct ip));
    } else {
        sum = checksum2((int *)ip, sizeof(struct ip), option, optionLen);
    }

    if (sum != 0 && sum != 0xFFFF) {
        printf("bad ip checksum\n");
        return -1;
    }

    int plen = ntohs(ip->ip_len) - ip->ip_hl * 4;
    int no = IpRecvBufAdd(ntohs(ip->ip_id));
    int off = (ntohs(ip->ip_off) & IP_OFFMASK) * 8;
    memcpy(IpRecvBuf[no].data + off, ptr, plen);

    // IP_MFビットがオンの場合はまだフラグメントされたデータが続く
    if (!(ntohs(ip->ip_off) & IP_MF)) {
        IpRecvBuf[no].len = off + plen;
        if (ip ->ip_p == IPPROTO_ICMP) {
            IcmpRecv(soc, raw, raw_len, eh, ip, IpRecvBuf[no].data, IpRecvBuf[no].len);
        }
        IpRecvBufDel(ntohs(ip->ip_id));
    }

    return 0;
}

int IpSendLink(int soc, int smac[6], int dmac[6], struct in_addr *saddr, struct in_addr *daddr,
           int proto, int dontFlagment, int ttl, int *data, int len) {
    if (dontFlagment && len > Param.MTU - sizeof(struct ip)) {
        printf("IpSend:data too long:%d\n", len);
        return -1;
    }

    int id = random();
    int *dptr = data;
    int lest = len;

    while (lest > 0) {
        int sndLen, flagment;
        if (lest > Param.MTU - sizeof(struct ip)) {
            sndLen = (Param.MTU - sizeof(struct ip)) / 8 * 8;
            flagment = 1;
        } else {
            sndLen = lest;
            flagment = 0;
        }

        int buf[ETHERMTU];
        int *ptr = buf;
        struct ip *ip = (struct ip *)ptr;
        memset(ip, 0, sizeof(struct ip));
        ip->ip_v = 4;
        ip->ip_hl = 5;
        ip->ip_len = htons(sizeof(struct ip) + sndLen);
        ip->ip_id = htons(id);
        int off = (dptr - data) / 8;
        if (dontFlagment) {
            ip->ip_off = htons(IP_DF);
        } else if (flagment) {
            ip->ip_off = htons((IP_MF) | (off & IP_OFFMASK));
        } else {
            ip->ip_off = htons((0) | (off & IP_OFFMASK));
        }
        ip->ip_ttl = ttl;
        ip->ip_p = proto;
        ip->ip_src.s_addr = saddr->s_addr;
        ip->ip_dst.s_addr = daddr->s_addr;
        ip->ip_sum = 0;
        ip->ip_sum = checksum((int *)ip, sizeof(struct ip));
        ptr += sizeof(struct ip);

        memcpy(ptr, dptr, sndLen);
        ptr += sndLen;

        EtherSend(soc, smac, dmac, ETHERTYPE_IP, buf, ptr - buf);
        print_ip(ip);

        dptr += sndLen;
        lest -= sndLen;
    }

    return 0;
}

int IpSend(int soc, struct in_addr *saddr, struct in_addr *daddr,
           int proto, int dontFlagment, int ttl, int *data, int len) {
    int dmac[6];
    if (GetTargetMac(soc, daddr, dmac, 0)) {
        return IpSendLink(soc, Param.vmac, dmac, saddr, daddr, proto, dontFlagment, ttl, data, len);
    } else {
        char buf[80];
        printf("IpSend:%s Destination Host Unreachable\n", inet_ntop(AF_INET, daddr, buf, sizeof(buf)));
        return -1;
    }
}