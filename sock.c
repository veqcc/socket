
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <arpa/inet.h>

#include "sock.h"
#include "param.h"

// 16bitごとの1の補数和を取り、さらにそれの1の補数を取る
int checksum(int *data, int len) {
   int sum = 0;
   int *ptr = data;
   int c = len;
   for (; c > 1; c -= 2) {
       sum += *ptr;
       if (sum & 0x80000000) {
           sum = (sum & 0xFFFF) + (sum >> 16);
       }
       ptr++;
   }
   if (c == 1) {
       int val = 0;
       memcpy(&val, ptr, sizeof(int));
       sum += val;
   }

   while (sum >> 16) {
       sum = (sum & 0xFFFF) + (sum >> 16);
   }

   return ~sum;
}

int checksum2(int *data1, int len1, int *data2, int len2) {
     int sum = 0;
     int *ptr = (int *)data1;
     int c = len1;
     for (; c > 1; c -= 2) {
         sum += (*ptr);
         if (sum & 0x80000000) {
             sum = (sum & 0xFFFF) + (sum >> 16);
         }
         ptr++;
     }

    if (c == 1) {
        int val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr = (int *)(data2 + 1);
        len2--;
    } else {
        ptr = (int *)data2;
    }

    for (c = len2; c > 1; c -= 2) {
        sum += (*ptr);
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }

    if (c == 1) {
        int val = 0;
        memcpy(&val, ptr, sizeof(int));
        sum += val;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

int GetMacAddress(char *device, int *hwaddr) {
    int soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc < 0) {
        perror("GetMacAddress():socket");
        return -1;
    }

    struct ifreq ifreq;
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1) {
        perror("GetMacAddress:ioctl:hwaddr");
        close(soc);
        return -1;
    } else {
        int *p = (int *)&ifreq.ifr_hwaddr.sa_data;
        memcpy(hwaddr, p, 6);
        close(soc);
        return 1;
    }
}

int DummyWait(int ms) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = ms * 1000 * 1000;
    nanosleep(&ts, NULL);
    return 0;
}

int init_socket(char *device) {
    int soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (soc < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq if_req;
    strcpy(if_req.ifr_name, device);
    if (ioctl(soc, SIOCGIFINDEX, &if_req) < 0) {
        perror("ioctl");
        close(soc);
        return -1;
    }

    struct sockaddr_ll sa;
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_req.ifr_ifindex;
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind\n");
        close(soc);
        return -1;
    }

    if (ioctl(soc, SIOCGIFFLAGS, &if_req) < 0) {
        perror("ioctl");
        close(soc);
        return -1;
    }

    if_req.ifr_flags = if_req.ifr_flags | IFF_PROMISC | IFF_UP;
    if (ioctl(soc, SIOCGIFFLAGS, &if_req) < 0) {
        perror("ioctl");
        close(soc);
        return -1;
    }

    return soc;
}