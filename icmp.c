
#include <stdio.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <zconf.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "ip.h"
#include "sock.h"
#include "icmp.h"
#include "param.h"
#include "ether.h"

extern PARAM Param;

#define ECHO_HEADER_SIZE 8
#define PING_SEND_NO 4

typedef struct {
    // pingのRound Trip Timeを計算できるよう、送信時刻を保持
    struct timeval sendTime;
} PING_DATA;

PING_DATA PingData[PING_SEND_NO];

int print_icmp(struct icmp *icmp) {
    static char *icmp_type[] = {
            "Echo Reply",
            "undefined",
            "undefined",
            "Destination Unreachable",
            "Source Quench",
            "Redirect",
            "undefined",
            "undefined",
            "Echo Request",
            "Router Adverisement",
            "Router Selection",
            "Time Exceeded for Datagram",
            "Parameter Problem on Datagram",
            "Timestamp Request",
            "Timestamp Reply",
            "Information Request",
            "Information Reply",
            "Address Mask Request",
            "Address Mask Reply"
    };

    printf("icmp-----------------------------------\n");
    printf("icmp_type = %u", icmp->icmp_type);
    if (icmp->icmp_type <= 18) {
        printf("(%s),", icmp_type[icmp->icmp_type]);
    } else {
        printf("(undefined),");
    }
    printf("icmp_code = %u,", icmp->icmp_code);
    printf("icmp_cksum = %u\n", ntohs(icmp->icmp_cksum));
    if (icmp->icmp_type == 0 || icmp->icmp_type == 8) {
        printf("icmp_id = %u,", ntohs(icmp->icmp_id));
        printf("icmp_seq = %u\n", ntohs(icmp->icmp_seq));
    }
    printf("icmp-----------------------------------\n");

    return 0;
}

int IcmpSendEchoReply(int soc, struct ip *ip, struct icmp *r_icmp, int *data, int len, int ip_ttl) {
    int buf[64 * 1024];
    int *ptr = buf;
    struct icmp *icmp = (struct icmp *)ptr;
    memset(icmp, 0, sizeof(struct icmp));
    icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_code = 0;
    icmp->icmp_hun.ih_idseq.icd_id = r_icmp->icmp_hun.ih_idseq.icd_id;
    icmp->icmp_hun.ih_idseq.icd_seq = r_icmp->icmp_hun.ih_idseq.icd_seq;
    icmp->icmp_cksum = 0;

    ptr += ECHO_HEADER_SIZE;
    memcpy(ptr, data, len);
    ptr += len;
    icmp->icmp_cksum = checksum(buf, ptr - buf);

    printf(" === ICMP reply ===\n");
    IpSend(soc, &ip->ip_dst, &ip->ip_src, IPPROTO_ICMP, 0, ip_ttl, buf, ptr - buf);
    print_icmp(icmp);
    printf(" ==================\n");

    return 0;
}

int IcmpSendEcho(int soc, struct in_addr *daddr, int seqNo, int size) {
    int buf[64 * 1024];
    int *ptr = buf;
    struct icmp *icmp = (struct icmp *)ptr;
    memset(icmp, 0, sizeof(struct icmp));
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_hun.ih_idseq.icd_id = htons(getpid());
    icmp->icmp_hun.ih_idseq.icd_seq = htons(seqNo);
    icmp->icmp_cksum = 0;

    ptr += ECHO_HEADER_SIZE;

    int psize = size - ECHO_HEADER_SIZE;
    for (int i = 0; i < psize; i++) {
        *ptr = i & 0xFF;
        ptr++;
    }

    icmp->icmp_cksum = checksum(buf, ptr - buf);

    printf(" === ICMP echo === \n");
    IpSend(soc, &Param.vip, daddr, IPPROTO_ICMP, 0, Param.IpTTL, buf, ptr - buf);
    print_icmp(icmp);
}

int PingSend(int soc, struct in_addr *daddr, int size) {
    for (int i = 0; i < PING_SEND_NO; i++) {
        IcmpSendEcho(soc, daddr, i + 1, size);
        sleep(1);
    }

    return 0;
}

int PingCheckReply(struct ip *ip, struct icmp *icmp) {
    // idがプロセスidと一致しているかチェック
    if (ntohs(icmp->icmp_id) == getpid()) {
        int seqNo = ntohs(icmp->icmp_seq);
        if (seqNo > 0 && seqNo <= PING_SEND_NO) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            int seq = tv.tv_sec - PingData[seqNo - 1].sendTime.tv_sec;
            int useq = tv.tv_usec - PingData[seqNo - 1].sendTime.tv_usec;
            if (useq < 0) {
                seq--;
                useq = 10000 - useq;
            }

            char buf[80];
            printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%d.%03d ms\n",
                    ntohs(ip->ip_len),
                    inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf)),
                    ntohs((icmp->icmp_seq)),
                    ip->ip_ttl,
                    seq, useq);
        }
    }

    return 0;
}

int IcmpRecv(int soc, int *raw, int raw_len, struct ether_header *eh, struct ip *ip, int *data, int len) {
   int icmpSize = len;
   int *ptr = data;
   struct icmp *icmp = (struct icmp *)ptr;
   ptr += ECHO_HEADER_SIZE;
   len -= ECHO_HEADER_SIZE;

   int sum = checksum((int *)icmp, icmpSize);
   if (sum != 0 && sum != 0xFFFF) {
       printf("bad icmp checksum(%x, %x)\n", sum, icmp->icmp_cksum);
       return -1;
   }

   // 自分宛のIPアドレスであるならば以下を実行
   if (isTargetIPAddr(&ip->ip_dst)) {
       printf(" --- recv --- \n");
       // print_ether_header(eh);
       print_ip(ip);
       print_icmp(icmp);
       printf(" ------------ \n");

       if (icmp->icmp_type == ICMP_ECHO) {
           IcmpSendEchoReply(soc, ip, icmp, ptr, len, Param.IpTTL);
       } else if (icmp->icmp_type == ICMP_ECHOREPLY) {
           PingCheckReply(ip, icmp);
       }
   }

   return 0;
}