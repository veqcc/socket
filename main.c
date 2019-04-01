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
#include "sock.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "param.h"
#include "cmd.h"

int EndFlag = 0;
int DeviceSoc;
PARAM Param;

void *MyEthThread(void *arg) {
    int nready;
    struct pollfd targets[1];
    u_int8_t buf[2048];
    int len;

    targets[0].fd = DeviceSoc;
    targets[0].events = POLLIN | POLLERR;

    while (EndFlag == 0) {
        switch ((nready = poll(targets, 1, 1000))) { // PF_PACKETのDeviceSocをpollで監視
            case -1:
                if (errno != EINTR) {
                    perror("poll");
                }
                break;
            case 0:
                break;
            default:
                if (targets[0].revents & (POLLIN | POLLERR)) {
                    if ((len = read(DeviceSoc, buf, sizeof(buf))) <= 0) {
                        perror("read");
                    } else {
                        EtherRecv(DeviceSoc, buf, len); // イーサネットフレーム解析関数
                    }
                }
                break;
        }
    }

    return (NULL);
}

void *StdInThread(void *arg) {
    int nready;
    struct pollfd targets[1];
    char buf[2048];

    targets[0].fd = fileno(stdin);
    targets[0].events = POLLIN | POLLERR;

    while (EndFlag == 0) {
        switch ((nready = poll(targets, 1, 1000))) {
            case -1:
                if (errno != EINTR) {
                    perror("poll");
                }
                break;
            case 0:
                break;
            default:
                if (targets[0].revents & (POLLIN | POLLERR)) {
                    fgets(buf, sizeof(buf), stdin);
                    DoCmd(buf);
                }
                break;
        }
    }

    return (NULL);
}

void sig_term(int sig) { EndFlag = 1; }

int ending() {
    struct ifreq if_req;

    printf("ending\n");

    if (DeviceSoc != -1) {
        strcpy(if_req.ifr_name, Param.device);
        if (ioctl(DeviceSoc, SIOCGIFFLAGS, &if_req) < 0) {
            perror("ioctl");
        }

        if_req.ifr_flags = if_req.ifr_flags & ~IFF_PROMISC;
        if (ioctl(DeviceSoc, SIOCSIFFLAGS, &if_req) < 0) {
            perror("ioctl");
        }

        close(DeviceSoc);
        DeviceSoc = -1;
    }

    return (0);
}

int show_ifreq(char *name) {
    char buf1[80];
    int soc;
    struct ifreq ifreq;
    struct sockaddr_in addr;

    if ((soc = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return (-1);
    }

    strcpy(ifreq.ifr_name, name);

    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) == -1) {
        perror("ioctl:flags");
        close(soc);
        return (-1);
    }

    if (ifreq.ifr_flags & IFF_UP) {
        printf("UP ");
    }
    if (ifreq.ifr_flags & IFF_BROADCAST) {
        printf("BROADCAST ");
    }
    if (ifreq.ifr_flags & IFF_PROMISC) {
        printf("PROMISC ");
    }
    if (ifreq.ifr_flags & IFF_MULTICAST) {
        printf("MULTICAST ");
    }
    if (ifreq.ifr_flags & IFF_LOOPBACK) {
        printf("LOOPBACK ");
    }
    if (ifreq.ifr_flags & IFF_POINTOPOINT) {
        printf("P2P ");
    }
    printf("\n");

    if (ioctl(soc, SIOCGIFMTU, &ifreq) == -1) {
        perror("ioctl:mtu");
    } else {
        printf("mtu=%d\n", ifreq.ifr_mtu);
    }

    if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1) {
        perror("ioctl:addr");
    } else if (ifreq.ifr_addr.sa_family != AF_INET) {
        printf("not AF_INET\n");
    } else {
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        printf("myip=%s\n", inet_ntop(AF_INET, &addr.sin_addr, buf1, sizeof(buf1)));
        Param.myip = addr.sin_addr;
    }

    close(soc);

    if (GetMacAddress(name, Param.mymac) == -1) {
        printf("GetMacAddress:error");
    } else {
        printf("mymac=%s\n", my_ether_ntoa_r(Param.mymac, buf1));
    }

    return (0);
}

int main(int argc, char *argv[]) {
    char buf1[80];
    int i, paramFlag;
    pthread_attr_t attr;
    pthread_t thread_id;

    SetDefaultParam();

    paramFlag = 0;
    for (i = 1; i < argc; i++) {
        if (ReadParam(argv[1]) == -1) {
            exit(-1);
        }
        paramFlag = 1;
    }
    if (paramFlag == 0) {
        if (ReadParam("./MyEth.ini") == -1) {
            exit(-1);
        }
    }

    printf("IP-TTL=%d\n", Param.IpTTL);
    printf("MTU=%d\n", Param.MTU);

    srandom(time(NULL));

    IpRecvBufInit(); // IP受信バッファを-1(未使用)で初期化

    if ((DeviceSoc = init_socket(Param.device)) == -1) {
        exit(-1);
    }

    printf("device=%s\n", Param.device);
    printf("++++++++++++++++++++++++++++++++++++++++\n");
    show_ifreq(Param.device);
    printf("++++++++++++++++++++++++++++++++++++++++\n");

    printf("vmac=%s\n", my_ether_ntoa_r(Param.vmac, buf1));
    printf("vip=%s\n", inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)));
    printf("vmask=%s\n", inet_ntop(AF_INET, &Param.vmask, buf1, sizeof(buf1)));
    printf("gateway=%s\n", inet_ntop(AF_INET, &Param.gateway, buf1, sizeof(buf1)));

    signal(SIGINT, sig_term);
    signal(SIGTERM, sig_term);
    signal(SIGQUIT, sig_term);

    signal(SIGPIPE, SIG_IGN);

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 102400);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread_id, &attr, MyEthThread, NULL) != 0) {
        printf("pthread_create:error\n");
    }
    if (pthread_create(&thread_id, &attr, StdInThread, NULL) != 0) {
        printf("pthread_create:error\n");
    }

    if (ArpCheckGArp(DeviceSoc) == 0) { // IPアドレスの重複を確認
        printf("GArp check fail\n");
        return (-1);
    }

    while (EndFlag == 0) {
        sleep(1);
    }

    ending();

    return (0);
}