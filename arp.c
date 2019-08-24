
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "arp.h"
#include "ether.h"
#include "param.h"
#include "sock.h"

extern PARAM Param;

#define ARP_TABLE_NO 16

typedef struct {
    time_t timestamp;
    int mac[6];
    struct in_addr ipaddr;
} ARP_TABLE;

ARP_TABLE ArpTable[ARP_TABLE_NO];

pthread_rwlock_t ArpTableLock = PTHREAD_RWLOCK_INITIALIZER;

extern int AllZeroMac[6], BcastMac[6];

int ArpDelTable(struct in_addr *ipaddr) {
    pthread_rwlock_wrlock(&ArpTableLock);

    for (int i = 0; i < ARP_TABLE_NO; i++) {
        if (memcmp(ArpTable[i].mac, AllZeroMac, 6) != 0) {
            if (ArpTable[i].ipaddr.s_addr == ipaddr->s_addr) {
                memcpy(ArpTable[i].mac, AllZeroMac, 6);
                ArpTable[i].ipaddr.s_addr = 0;
                ArpTable[i].timestamp = 0;
                pthread_rwlock_unlock(&ArpTableLock);
                return 1;
            }
        }
    }

    pthread_rwlock_unlock(&ArpTableLock);
    return 0;
}

int ArpSearchTable(struct in_addr *ipaddr, int mac[6]) {
    pthread_rwlock_rdlock(&ArpTableLock);

    for (int i = 0; i < ARP_TABLE_NO; i++) {
        if (memcmp(ArpTable[i].mac, AllZeroMac, 6) != 0) {
            if (ArpTable[i].ipaddr.s_addr == ipaddr->s_addr) {
                memcpy(mac, ArpTable[i].mac, 6);
                pthread_rwlock_unlock(&ArpTableLock);
                return 1;
            }
        }
    }

    pthread_rwlock_unlock(&ArpTableLock);
    return 0;
}

int ArpShowTable() {
    pthread_rwlock_rdlock(&ArpTableLock);

    for (int i = 0; i < ARP_TABLE_NO; i++) {
        if (memcmp(ArpTable[i].mac, AllZeroMac, 6) != 0) {
            char buf1[80], buf2[80];
            printf("(%s) at %s\n",
                    inet_ntop(AF_INET, &ArpTable[i].ipaddr, buf1, sizeof(buf1)),
                    my_ether_ntoa_r(ArpTable[i].mac, buf2));
        }
    }

    pthread_rwlock_unlock(&ArpTableLock);
    return 0;
}

// 指定したIPアドレスに対するMACアドレスを調べる
int GetTargetMac(int soc, struct in_addr *daddr, int dmac[6], int gratuitous) {
    struct in_addr addr;
    if (isSameSubnet(daddr)) {
        addr.s_addr = daddr->s_addr;
    } else {
        addr.s_addr = Param.gateway.s_addr;
    }

    int count = 0;
    while (!ArpSearchTable(&addr, dmac)) {
        if (gratuitous) {
            // gratuitousが1の場合、Gratuitous ARPを送信し、応答があるか調べてIP重複チェック
            ArpSendRequestGratuitous(soc, &addr);
        } else {
            // ARPテーブルに存在すればそれを使い、なければARP要求を送信してARPテーブルにデータが格納されるまでリトライ
            ArpSendRequest(soc, &addr);
        }

        DummyWait(DUMMY_WAIT_MS*(count+1));
        count++;
        if (count > RETRY_COUNT) {
            return 0;
        }
    }
    return 1;
}

// イーサネットにARPパケットを送信する
int ArpSend(int soc, int op, int e_smac[6], int e_dmac[6], int smac[6], int dmac[6], int saddr[4], int daddr[4]) {
    struct ether_arp arp;
    memset(&arp, 0, sizeof(struct ether_arp));
    arp.arp_hrd = htons(ARPHRD_ETHER);
    arp.arp_pro = htons(ETHERTYPE_IP);
    arp.arp_hln = 6;
    arp.arp_pln = 4;
    arp.arp_op = htons(op);
    memcpy(arp.arp_sha, smac, 6);
    memcpy(arp.arp_tha, dmac, 6);
    memcpy(arp.arp_spa, saddr, 4);
    memcpy(arp.arp_tpa, daddr, 4);

    printf(" === ARP === \n")
    EtherSend(soc, e_smac, e_dmac, ETHERTYPE_ARP, &arp, sizeof(struct ether_arp));
    // print_ether_arp(&arp);
    printf("\n");
    return 0;
}

int ArpSendRequestGratuitous(int soc, struct in_addr *targetIp) {
    union {
        int l, c[4];
    } saddr, daddr;

    // Gratuitous ARPでは、source IP addressを0にし、受信した相手のARP Tableに影響を与えないようにする
    saddr.l = 0;
    daddr.l = targetIp->s_addr;
    ArpSend(soc, ARPOP_REQUEST, Param.vmac, BcastMac, Param.vmac, AllZeroMac, saddr.c, daddr.c);
    return 0;
}

int ArpSendRequest(int soc, struct in_addr *targetIp) {
    union {
        int l, c[4];
    } saddr, daddr;

    saddr.l = Param.vip.s_addr;
    daddr.l = targetIp->s_addr;
    ArpSend(soc, ARPOP_REQUEST, Param.vmac, BcastMac, Param.vmac, AllZeroMac, saddr.c, daddr.c);
    return 0;
}

// IP重複を調べる
// 自ら使おうとしているIPアドレスが他に存在しないかを調べる
int ArpCheckGArp(int soc) {
    int dmac[6];
    char buf1[80], buf2[80];

    // gratuitousフラグを1にして、Gratuitous ARPを送信
    if (GetTargetMac(soc, &Param.vip, dmac, 1)) {

        // 応答があった場合IP重複とみなす
        printf("ArpCheckGArp:%s use %s\n",
                inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)),
                my_ether_ntoa_r(dmac, buf2));
        return 0;
    }
    return 1;
}