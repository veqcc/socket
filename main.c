#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <pthread.h>

#include "icmp.h"
#include "arp.h"
#include "ip.h"
#include "ether.h"
#include "param.h"
#include "sock.h"
#include "cmd.h"

int EndFlag = 0;

// Descriptor of PF_PACKET
int DeviceSoc;

PARAM Param;

void *MyEthThread() {
    struct pollfd targets[1];
    int buf[2048];

    targets[0].fd = DeviceSoc;
    targets[0].events = POLLIN | POLLERR;

    while (EndFlag == 0) {
        int ready = poll(targets, 1, 1000);
        if (ready == -1) {
            // errno : number of last error
            // EINTR : interrupted by system call
            if (errno != EINTR) {
                perror("poll");
            }
        } else if (ready != 0) {
            if (targets[0].revents & (POLLIN | POLLERR)) {
                int len = read(DeviceSoc, buf, sizeof(buf));
                if (len <= 0) {
                    perror("read");
                } else {
                    EtherRecv(DeviceSoc, buf, len);
                }
            }
        }
    }
}

void *StdInThread() {
    struct pollfd targets[2];
    char buf[2048];

    targets[0].fd = fileno(stdin);
    targets[0].events = POLLIN | POLLERR;

    while (EndFlag == 0) {
        int ready = poll(targets, 1, 1000);
        if (ready == -1) {
            if (errno != EINTR) {
                perror("poll");
            }
        } else if (ready != 0) {
            if (targets[0].revents & (POLLIN | POLLERR)) {
                fgets(buf, sizeof(buf), stdin);
                DoCmd(buf);
            }
        }
    }
}

void sig_term(int sig) {
    EndFlag = 1;
}

void ending() {
    printf("ending\n");

    if (DeviceSoc != -1) {
        struct ifreq ifreq;
        strcpy(ifreq.ifr_name, Param.device);
        if (ioctl(DeviceSoc, SIOCGIFFLAGS, &ifreq) < 0) {
            printf("ioctl");
        }

        ifreq.ifr_flags = ifreq.ifr_flags &~ IFF_PROMISC;
        if (ioctl(DeviceSoc, SIOCSIFFLAGS, &ifreq) < 0) {
            perror("ioctl");
        }

        close(DeviceSoc);
        DeviceSoc = -1;
    }
}

void show_ifreq(char *device) {
    int soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        perror("socket");
        return;
    }

    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, device);

    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) == -1) {
        perror("ioctl:flags");
        close(soc);
        return;
    }

    if (ifreq.ifr_flags & IFF_UP)          printf("UP ");
    if (ifreq.ifr_flags & IFF_BROADCAST)   printf("BROADCAST ");
    if (ifreq.ifr_flags & IFF_PROMISC)     printf("PROMISC ");
    if (ifreq.ifr_flags & IFF_MULTICAST)   printf("MULTICAST ");
    if (ifreq.ifr_flags & IFF_LOOPBACK)    printf("LOOPBACK ");
    if (ifreq.ifr_flags & IFF_POINTOPOINT) printf("P2P ");
    printf("\n");

    if (ioctl(soc, SIOCGIFMTU, &ifreq) == -1) {
        perror("ioctl:mtu");
    } else {
        printf("mtu = %d\n", ifreq.ifr_mtu);
    }

    char buf[80];
    if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1) {
        perror("ioctl:addr");
    } else if (ifreq.ifr_addr.sa_family != AF_INET) {
        printf("not AF_INET\n");
    } else {
        struct sockaddr_in addr;
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        printf("myip = %s\n", inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf)));
        Param.myip = addr.sin_addr;
    }

    close(soc);

    if (GetMacAddress(device, Param.mymac) == -1) {
        printf("GetMacAddress:error");
    } else {
        printf("mymac = %s\n", my_ether_ntoa_r(Param.mymac, buf));
    }
}

int main(int argc, char *argv[]) {
    SetDefaultParam();

    if (argc == 1) {
        if (ReadParam("./MyEth.ini") == -1) {
            exit(-1);
        }
    } else {
        for (int i = 1; i < argc; i++) {
            if (ReadParam(argv[i]) == -1) {
                exit(-1);
            }
        }
    }

    printf("IP-TTL = %d\n", Param.IpTTL);
    printf("MTU    = %d\n", Param.MTU);

    srandom(time(NULL));

    IpRecvBufInit();

    DeviceSoc = init_socket(Param.device);
    if (DeviceSoc == -1) {
        exit(-1);
    }

    printf("device = %s", Param.device);
    printf("\n");
    show_ifreq(Param.device);
    printf("\n");

    char buf[80];
    printf("vmac    = %s\n", my_ether_ntoa_r(Param.vmac, buf));
    printf("vip     = %s\n", inet_ntop(AF_INET, &Param.vip, buf, sizeof(buf)));
    printf("vmask   = %s\n", inet_ntop(AF_INET, &Param.vmask, buf, sizeof(buf)));
    printf("gateway = %s\n", inet_ntop(AF_INET, &Param.gateway, buf, sizeof(buf)));

    signal(SIGINT, sig_term);
    signal(SIGTERM, sig_term);
    signal(SIGQUIT, sig_term);
    signal(SIGPIPE, SIG_IGN);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 102400);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_t thread_id;
    if (pthread_create(&thread_id, &attr, MyEthThread, NULL) != 0) {
        printf("pthread_create:error\n");
    }
    if (pthread_create(&thread_id, &attr, StdInThread, NULL) != 0) {
        printf("pthread_create:error\n");
    }

    if (ArpCheckGArp(DeviceSoc) == 0) {
        printf("GArp check fail\n");
        return -1;
    }

    while (EndFlag == 0) {
        sleep(1);
    }

    ending();

    return 0;
}