#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/ioctl.h>
#include	<netpacket/packet.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/if_ether.h>
#include	<netinet/tcp.h>
#include	<linux/if.h>
#include	<arpa/inet.h>
#include	<pthread.h>
#include	"sock.h"
#include	"ether.h"
#include	"ip.h"
#include	"tcp.h"
#include	"param.h"

extern PARAM Param;

struct pseudo_ip {
    struct in_addr ip_src;
    struct in_addr ip_dst;
    u_int8_t dummy;
    u_int8_t ip_p;
    u_int16_t ip_len;
};

#define	TCP_TABLE_NO (16)

typedef struct {
    u_int16_t myPort, dstPort;
    struct in_addr dstAddr;
    struct {
        u_int32_t una;    // 未確認の送信
        u_int32_t nxt;    // 次の送信
        u_int32_t wnd;    // 送信ウインドウ
        u_int32_t iss;    // 初期送信シーケンス番号
    } snd;
    struct {
        u_int32_t nxt;    // 次の受信
        u_int32_t wnd;    // 受信ウィンドウ
        u_int32_t irs;    // 初期受信シーケンス番号
    } rcv;
    int status;
} TCP_TABLE;

TCP_TABLE TcpTable[TCP_TABLE_NO];

pthread_rwlock_t TcpTableLock = PTHREAD_RWLOCK_INITIALIZER;

int print_tcp(struct tcphdr *tcp) {
    printf("tcp-----------------------------------------------------------------------------\n");

    printf("source=%u,", ntohs(tcp->source));
    printf("dest=%u\n", ntohs(tcp->dest));
    printf("seq=%u\n", ntohl(tcp->seq));
    printf("ack_seq=%u\n", ntohl(tcp->ack_seq));
    printf("doff=%u,", tcp->doff);
    printf("urg=%u,", tcp->urg);
    printf("ack=%u,", tcp->ack);
    printf("psh=%u,", tcp->psh);
    printf("rst=%u,", tcp->rst);
    printf("syn=%u,", tcp->syn);
    printf("fin=%u,", tcp->fin);
    printf("window=%u\n", ntohs(tcp->window));
    printf("check=%04x,", ntohs(tcp->check));
    printf("urg_ptr=%u\n", ntohs(tcp->urg_ptr));

    return (0);
}

int print_tcp_optpad(unsigned char *data,int size) {
    int i;

    printf("option,pad(%d)=", size);
    for (i = 0; i < size; i++) {
        if (i != 0) {
            printf(",");
        }
        printf("%02x", *data);
        data++;
    }
    printf("\n");

    return (0);
}

char *TcpStatusStr(int status) {
    switch (status) {
        case TCP_ESTABLISHED:
            return ("ESTABLISHED");
        case TCP_SYN_SENT:
            return ("SYN_SENT");
        case TCP_SYN_RECV:
            return ("SYN_RECV");
        case TCP_FIN_WAIT1:
            return ("FIN_WAIT1");
        case TCP_FIN_WAIT2:
            return ("FIN_WAIT2");
        case TCP_TIME_WAIT:
            return ("TIME_WAIT");
        case TCP_CLOSE:
            return ("CLOSE");
        case TCP_CLOSE_WAIT:
            return ("CLOSE_WAIT");
        case TCP_LAST_ACK:
            return ("LAST_ACK");
        case TCP_LISTEN:
            return ("LISTEN");
        case TCP_CLOSING:
            return ("CLOSING");
        default:
            return ("undefine");
    }
}

u_int16_t TcpChecksum(struct in_addr *saddr,struct in_addr *daddr,u_int8_t proto,u_int8_t *data,int len) {
    struct pseudo_ip p_ip;
    u_int16_t sum;

    memset(&p_ip, 0, sizeof(struct pseudo_ip));
    p_ip.ip_src.s_addr = saddr->s_addr;
    p_ip.ip_dst.s_addr = daddr->s_addr;
    p_ip.ip_p = proto;
    p_ip.ip_len = htons(len);

    sum = checksum2((u_int8_t * ) & p_ip, sizeof(struct pseudo_ip), data, len);
    return (sum);
}

int TcpAddTable(u_int16_t port) {
    int i, freeNo;

    pthread_rwlock_wrlock(&TcpTableLock);

    freeNo = -1;
    for (i = 0; i < TCP_TABLE_NO; i++) {
        if (TcpTable[i].myPort == port) {
            printf("TcpAddTable:port %d:already exist\n", port);
            pthread_rwlock_unlock(&TcpTableLock);
            return (-1);
        } else if (TcpTable[i].myPort == 0) {
            if (freeNo == -1) {
                freeNo = i;
            }
        }
    }
    if (freeNo == -1) {
        printf("TcpAddTable:no free table\n");
        pthread_rwlock_unlock(&TcpTableLock);
        return (-1);
    }

    memset(&TcpTable[freeNo], 0, sizeof(TCP_TABLE));
    TcpTable[freeNo].myPort = port;
    TcpTable[freeNo].snd.iss = TcpTable[freeNo].snd.una = TcpTable[freeNo].snd.nxt = random();
    TcpTable[freeNo].rcv.irs = TcpTable[freeNo].rcv.nxt = 0;
    TcpTable[freeNo].snd.wnd = TCP_INIT_WINDOW;
    TcpTable[freeNo].status = TCP_CLOSE;

    pthread_rwlock_unlock(&TcpTableLock);

    return (freeNo);
}

int TcpSearchTable(u_int16_t port) {
    int i;

    pthread_rwlock_rdlock(&TcpTableLock);

    for (i = 0; i < TCP_TABLE_NO; i++) {
        if (TcpTable[i].myPort == port) {
            pthread_rwlock_unlock(&TcpTableLock);
            return (i);
        }
    }

    pthread_rwlock_unlock(&TcpTableLock);

    return (-1);
}

int TcpShowTable() {
    int i;
    char buf1[80], buf2[80];

    pthread_rwlock_rdlock(&TcpTableLock);

    for (i = 0; i < TCP_TABLE_NO; i++) {
        if (TcpTable[i].myPort != 0) {
            if (TcpTable[i].status == TCP_ESTABLISHED) {
                printf("TCP:%d:%u=%s:%u-%s:%u:%s\n", i, TcpTable[i].myPort,
                       inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)), TcpTable[i].myPort,
                       inet_ntop(AF_INET, &TcpTable[i].dstAddr, buf2, sizeof(buf2)), TcpTable[i].dstPort,
                       TcpStatusStr(TcpTable[i].status));
            } else {
                printf("TCP:%d:%u=%s:%u:%s\n", i, TcpTable[i].myPort,
                       inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)), TcpTable[i].myPort,
                       TcpStatusStr(TcpTable[i].status));
            }
        }
    }

    pthread_rwlock_unlock(&TcpTableLock);

    return (0);
}

u_int16_t TcpSearchFreePort() {
    u_int16_t i;

    for (i = 32768; i < 61000; i++) {
        if (TcpSearchTable(i) == -1) {
            return (i);
        }
    }

    return (0);
}

int TcpSocketListen(u_int16_t port) {
    int no;

    if (port == 0) {
        if ((port = TcpSearchFreePort()) == 0) {
            printf("TcpSocket:no free port\n");
            return (-1);
        }
    }
    no = TcpAddTable(port);
    if (no == -1) {
        return (-1);
    }
    TcpTable[no].status = TCP_LISTEN;
    return (no);
}

int TcpSocketClose(u_int16_t port) {
    int no;

    no = TcpSearchTable(port);
    if (no == -1) {
        printf("TcpSocketClose:%u:not exists\n", port);
        return (-1);
    }
    pthread_rwlock_wrlock(&TcpTableLock);
    TcpTable[no].myPort = 0;
    pthread_rwlock_unlock(&TcpTableLock);

    return (0);
}

int TcpSendSyn(int soc,int no,int ackFlag) {
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *) ptr;
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);
    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;
    tcp->urg = 0;
    tcp->ack = ackFlag;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 1;
    tcp->fin = 0;
    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *) sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return (0);
}

int TcpSendFin(int soc,int no) {
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *) ptr;
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);
    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 1;
    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *) sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return (0);
}

int TcpSendRst(int soc,int no) {
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *) ptr;
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);
    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 1;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *) sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return (0);
}

int TcpSendAck(int soc,int no) {
    u_int8_t *ptr;
    u_int8_t sbuf[sizeof(struct ether_header) + 1500];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *) ptr;
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);
    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *) sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return (0);
}

int TcpSendRstDirect(int soc,struct ether_header *r_eh,struct ip *r_ip,struct tcphdr *r_tcp) {
    u_int8_t *ptr;
    u_int8_t sbuf[sizeof(struct ether_header) + 1500];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *) ptr;
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->seq = r_tcp->ack_seq;
    tcp->ack_seq = htonl(ntohl(r_tcp->seq) + 1);
    tcp->source = r_tcp->dest;
    tcp->dest = r_tcp->source;
    tcp->doff = 5;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 1;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = 0;
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &r_ip->ip_src, IPPROTO_TCP, (u_int8_t *) sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &r_ip->ip_src, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    return (0);
}

int TcpConnect(int soc,u_int16_t sport,struct in_addr *daddr,u_int16_t dport) {
    int count, no;

    if ((no = TcpAddTable(sport)) == -1) {
        return (-1);
    }

    TcpTable[no].dstPort = dport;
    TcpTable[no].dstAddr.s_addr = daddr->s_addr;

    TcpTable[no].status = TCP_SYN_SENT;
    count = 0;
    do {
        TcpSendSyn(soc, no, 0);
        DummyWait(DUMMY_WAIT_MS * (count + 1));
        printf("TcpConnect:%s\n", TcpStatusStr(TcpTable[no].status));
        count++;
        if (count > RETRY_COUNT) {
            printf("TcpConnect:retry over\n");
            TcpSocketClose(sport);
            return (0);
        }
    } while (TcpTable[no].status != TCP_ESTABLISHED);

    printf("TcpConnect:success\n");

    return (1);
}

int TcpClose(int soc,u_int16_t sport) {
    int count, no;
    time_t now_t;

    if ((no = TcpSearchTable(sport)) == -1) {
        return (-1);
    }

    if (TcpTable[no].status == TCP_ESTABLISHED) {
        TcpTable[no].status = TCP_FIN_WAIT1;
        count = 0;
        do {
            TcpSendFin(soc, no);
            DummyWait(DUMMY_WAIT_MS * (count + 1));
            printf("TcpClose:status=%s\n", TcpStatusStr(TcpTable[no].status));
            count++;
            if (count > RETRY_COUNT) {
                printf("TcpClose:retry over\n");
                TcpSocketClose(sport);
                return (0);
            }
        } while (TcpTable[no].status == TCP_FIN_WAIT1);

        count = 0;
        while (TcpTable[no].status != TCP_TIME_WAIT && TcpTable[no].status != TCP_CLOSE) {
            DummyWait(DUMMY_WAIT_MS * (count + 1));
            printf("TcpClose:status=%s\n", TcpStatusStr(TcpTable[no].status));
            count++;
            if (count > RETRY_COUNT) {
                printf("TcpClose:retry over\n");
                TcpSocketClose(sport);
                return (0);
            }
        }

        if (TcpTable[no].status != TCP_CLOSE) {
            now_t = time(NULL);
            while (time(NULL) - now_t < TCP_FIN_TIMEOUT) {
                printf("TcpClose:status=%s\n", TcpStatusStr(TcpTable[no].status));
                sleep(1);
            }
            TcpTable[no].status = TCP_CLOSE;
        }
    }

    printf("TcpClose:status=%s:success\n", TcpStatusStr(TcpTable[no].status));

    if (TcpTable[no].myPort != 0) {
        TcpSocketClose(sport);
    }

    return (1);
}

int TcpReset(int soc,u_int16_t sport) {
    int no;

    if ((no = TcpSearchTable(sport)) == -1) {
        return (-1);
    }

    TcpSendRst(soc, no);

    TcpSocketClose(sport);

    return (1);
}

int TcpAllSocketClose(int soc) {
    int i;

    for (i = 0; i < TCP_TABLE_NO; i++) {
        if (TcpTable[i].myPort != 0 && TcpTable[i].status == TCP_ESTABLISHED) {
            TcpClose(soc, TcpTable[i].myPort);
        }
    }

    return (0);
}

int TcpSendData(int soc,u_int16_t sport,u_int8_t *data,int len) {
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    int no;
    struct tcphdr *tcp;

    if ((no = TcpSearchTable(sport)) == -1) {
        return (-1);
    }

    if (TcpTable[no].status != TCP_ESTABLISHED) {
        printf("TcpSend:not established\n");
        return (-1);
    }

    ptr = sbuf;
    tcp = (struct tcphdr *) ptr;
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);
    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;
    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    memcpy(ptr, data, len);
    ptr += len;

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *) sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 0, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    print_hex(data, len);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una + len;

    return (0);
}

int TcpSend(int soc,u_int16_t sport,u_int8_t *data,int len) {
    u_int8_t *ptr;
    int count, no;
    int lest, sndLen;

    if ((no = TcpSearchTable(sport)) == -1) {
        return (-1);
    }

    ptr = data;
    lest = len;

    while (lest > 0) {
        if (lest >= TcpTable[no].rcv.wnd) {
            sndLen = TcpTable[no].rcv.wnd;
        } else if (lest >= Param.MSS) {
            sndLen = Param.MSS;
        } else {
            sndLen = lest;
        }

        printf("TcpSend:offset=%ld,len=%d,lest=%d\n", ptr - data, sndLen, lest);

        count = 0;
        do {
            TcpSendData(soc, sport, ptr, sndLen);
            DummyWait(DUMMY_WAIT_MS * (count + 1));
            printf("TcpSend:una=%u,nextSeq=%u\n", TcpTable[no].snd.una - TcpTable[no].snd.iss,
                   TcpTable[no].snd.nxt - TcpTable[no].snd.iss);
            count++;
            if (count > RETRY_COUNT) {
                printf("TcpSend:retry over\n");
                return (0);
            }
        } while (TcpTable[no].snd.una != TcpTable[no].snd.nxt);

        ptr += sndLen;
        lest -= sndLen;
    }

    printf("TcpSend:una=%u,nextSeq=%u:success\n", TcpTable[no].snd.una - TcpTable[no].snd.iss,
           TcpTable[no].snd.nxt - TcpTable[no].snd.iss);

    return (1);
}

int TcpRecv(int soc,struct ether_header *eh,struct ip *ip,u_int8_t *data,int len) {
    struct tcphdr *tcp;
    u_int8_t *ptr = data;
    u_int16_t sum;
    int no, lest, tcplen;

    tcplen = len;

    sum = TcpChecksum(&ip->ip_src, &ip->ip_dst, ip->ip_p, data, tcplen);
    if (sum != 0 && sum != 0xFFFF) {
        printf("TcpRecv:bad tcp checksum(%x)\n", sum);
        return (-1);
    }

    tcp = (struct tcphdr *) ptr;
    ptr += sizeof(struct tcphdr);
    tcplen -= sizeof(struct tcphdr);

    printf("--- recv ---[\n");
    print_ether_header(eh);
    print_ip(ip);
    print_tcp(tcp);
    lest = tcp->doff * 4 - sizeof(struct tcphdr);
    if (lest > 0) {
        print_tcp_optpad(ptr, lest);
        ptr += lest;
        tcplen -= lest;
    }
    print_hex(ptr, tcplen);
    printf("]\n");

    if ((no = TcpSearchTable(ntohs(tcp->dest))) != -1) {
        if (TcpTable[no].rcv.nxt != 0 && ntohl(tcp->seq) != TcpTable[no].rcv.nxt) {
            printf("TcpRecv:%d:seq(%u)!=rcv.nxt(%u)\n", no, ntohl(tcp->seq), TcpTable[no].rcv.nxt);
        } else {
            if (TcpTable[no].status == TCP_SYN_SENT) {
                if (tcp->rst == 1) {
                    printf("TcpRecv:%d:SYN_SENT:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                } else if (tcp->syn == 1) {
                    printf("TcpRecv:%d:SYN_SENT:syn\n", no);
                    TcpTable[no].status = TCP_SYN_RECV;
                    if (tcp->ack == 1) {
                        printf("TcpRecv:SYN_RECV:syn-ack:%d\n", no);
                        TcpTable[no].status = TCP_ESTABLISHED;
                    }
                    TcpTable[no].rcv.irs = ntohl(tcp->seq);
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + 1;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                }
            } else if (TcpTable[no].status == TCP_SYN_RECV) {
                if (tcp->rst == 1) {
                    printf("TcpRecv:%d:SYN_RECV:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                } else if (tcp->ack == 1) {
                    printf("TcpRecv:%d:SYN_RECV:ack\n", no);
                    TcpTable[no].status = TCP_ESTABLISHED;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            } else if (TcpTable[no].status == TCP_LISTEN) {
                if (tcp->syn == 1) {
                    printf("TcpRecv:%d:LISTEN:syn\n", no);
                    TcpTable[no].status = TCP_SYN_RECV;
                    TcpTable[no].dstAddr.s_addr = ip->ip_src.s_addr;
                    TcpTable[no].dstPort = ntohs(tcp->source);
                    TcpTable[no].rcv.irs = ntohl(tcp->seq) + 1;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + 1;
                    TcpSendSyn(soc, no, 1);
                }
            } else if (TcpTable[no].status == TCP_FIN_WAIT1) {
                if (tcp->rst == 1) {
                    printf("TcpRecv:%d:FIN_WAIT1:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                } else if (tcp->fin == 1) {
                    printf("TcpRecv:%d:FIN_WAIT1:fin\n", no);
                    TcpTable[no].status = TCP_CLOSING;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen + 1;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                    if (tcp->ack == 1) {
                        printf("TcpRecv:TCP_CLOSE:fin-ack:%d\n", no);
                        TcpTable[no].status = TCP_TIME_WAIT;
                    }
                } else if (tcp->ack == 1) {
                    printf("TcpRecv:%d:FIN_WAIT1:ack\n", no);
                    TcpTable[no].status = TCP_FIN_WAIT2;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            } else if (TcpTable[no].status == TCP_FIN_WAIT2) {
                if (tcp->rst == 1) {
                    printf("TcpRecv:%d:FIN_WAIT2:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                } else if (tcp->fin == 1) {
                    printf("TcpRecv:%d:FIN_WAIT2:fin\n", no);
                    TcpTable[no].status = TCP_TIME_WAIT;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen + 1;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                }
            } else if (TcpTable[no].status == TCP_CLOSING) {
                if (tcp->rst == 1) {
                    printf("TcpRecv:%d:CLOSING:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                } else if (tcp->ack == 1) {
                    printf("TcpRecv:%d:CLOSING:ack\n", no);
                    TcpTable[no].status = TCP_TIME_WAIT;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            } else if (TcpTable[no].status == TCP_CLOSE_WAIT) {
                if (tcp->rst == 1) {
                    printf("TcpRecv:%d:CLOSE_WAIT:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                } else if (tcp->ack == 1) {
                    printf("TcpRecv:%d:CLOSE_WAIT:ack\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
            } else if (TcpTable[no].status == TCP_ESTABLISHED) {
                if (tcp->rst == 1) {
                    printf("TcpRecv:%d:ESTABLISHED:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                } else if (tcp->fin == 1) {
                    printf("TcpRecv:%d:ESTABLISHED:fin\n", no);
                    TcpTable[no].status = TCP_CLOSE_WAIT;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen + 1;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendFin(soc, no);
                } else if (tcplen > 0) {
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                } else {
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            }
            TcpTable[no].rcv.wnd = ntohs(tcp->window);
        }
        printf("TcpRecv:%d:%s:S[%u,%u,%u,%u]:R[%u,%u,%u]\n", no, TcpStatusStr(TcpTable[no].status),
               TcpTable[no].snd.una - TcpTable[no].snd.iss, TcpTable[no].snd.nxt - TcpTable[no].snd.iss,
               TcpTable[no].snd.wnd, TcpTable[no].snd.iss,
               TcpTable[no].rcv.nxt - TcpTable[no].rcv.irs, TcpTable[no].rcv.wnd, TcpTable[no].rcv.irs);
    } else {
        printf("TcpRecv:no target:%u\n", ntohs(tcp->dest));
        TcpSendRstDirect(soc, eh, ip, tcp);
    }

    return (0);
}