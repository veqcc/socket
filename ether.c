
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>

#include "ip.h"
#include "arp.h"
#include "param.h"

extern PARAM Param;

int AllZeroMac[6] = {0, 0, 0, 0, 0, 0};
int BcastMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// バイナリ6バイトのMACアドレスから「:」区切りの文字列を得る
char *my_ether_ntoa_r(int *hwaddr, char *buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return buf;
}

// 「:」区切りのMACアドレス文字列から、バイナリ6バイトのMACアドレスを得る
int my_ather_aton(char *str, int *mac) {
    char *tmp = strdup(str);
    char *save_ptr = NULL;
    char *ptr = strtok_r(tmp, ":", &save_ptr);
    for (int c = 0; c < 6; c++) {
        if (ptr == NULL) {
            free(tmp);
            return -1;
        }
        mac[c] = strtol(ptr, NULL, 16);
        ptr = strtok_r(tmp, ":", &save_ptr);
    }
    free(tmp);
    return 0;
}

// smacからdmac宛にタイプtypeのデータを送信する
int EtherSend(int soc, int smac[6], int dmac[6], int type, int *data, int len) {
    if (len > ETHERMTU) {
        printf("EtherSend:data too long:%d\n", len);
        return -1;
    }

    // ヘッダー
    int buf[sizeof(struct ether_header) + ETHERMTU];
    int *ptr = buf;
    struct ether_header *eh = (struct ether_header *)ptr;
    memset(&eh, 0, sizeof(struct ether_header));
    memcpy(eh->ether_dhost, dmac, 6);
    memcpy(eh->ether_shost, smac, 6);
    eh->ether_type = htons(type);

    // データ本体
    ptr += sizeof(struct ether_header);
    memcpy(ptr, data, len);
    ptr += len;

    // フレームサイズがETH_ZLEN:60より小さい場合、末尾をパディング
    if ((ptr - buf) < ETH_ZLEN) {
        int padding = ETH_ZLEN - (ptr - buf);
        memset(ptr, 0, padding);
        ptr += padding;
    }

    // PF_PACKET用のディスクリプタに送信
    write(soc, buf, ptr - buf);
    // print_ether_header(eh);
    return 0;
}

int EtherRecv(int soc, int *in_ptr, int in_len) {
    struct ether_header *eh;
    int *ptr = in_ptr;
    int len = in_len;

    eh = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);
    len -= sizeof(struct ether_header);

    if (memcmp(eh->ether_dhost, BcastMac, 6) != 0 && memcmp(eh->ether_dhost, Param.vmac, 6) != 0) {
        return -1;
    }

    if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
        ArpRecv(soc, ptr, len);
    } else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
        IpRecv(soc, in_ptr, in_len, eh, ptr, len);
    }

    return 0;
}
