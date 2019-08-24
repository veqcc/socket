
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
#include "arp.h"
#include "ether.h"
#include "param.h"
#include "icmp.h"
#include "cmd.h"

extern int DeviceSoc;
extern PARAM Param;

int DoCmdArp(char **cmdline) {
    char *ptr = strtok_r(NULL, " \r\n", cmdline);
    if (ptr == NULL) {
        printf("DoCmdArp : no arg\n");
        return -1;
    }

    if (strcmp(ptr, "-a") == 0) {
        ArpShowTable();
        return 0;
    } else if (strcmp(ptr, "-d") == 0) {
        ptr = strtok_r(NULL, " \r\n", cmdline);
        if (ptr == NULL) {
            printf("DoCmdArp : -d no arg\n");
            return -1;
        }
        struct in_addr addr;
        inet_aton(ptr, &addr);
        if (ArpDelTable(&addr)) {
            printf("deleted\n");
        } else {
            printf("not exist\n");
        }
        return 0;
    } else {
        printf("DoCmdArp : [%s] unknown\n", ptr);
        return -1;
    }
}

int DoCmdPing(char **cmdline) {
    char *ptr = strtok_r(NULL, " \r\n", cmdline);
    if (ptr == NULL) {
        printf("DoCmdPing : no arg\n");
        return -1;
    }

    struct in_addr daddr;
    inet_aton(ptr, &daddr);
    int size;
    ptr = strtok_r(NULL, " \r\n", cmdline);
    if (ptr == NULL) {
        size = DEFAULT_PING_SIZE;
    } else {
        size = atoi(ptr);
    }

    PingSend(DeviceSoc, &daddr, size);
    return 0;
}

int DoCmdIfconfig() {
    char buf[80];
    printf("device  = %s\n", Param.device);
    printf("vmac    = %s\n", my_ether_ntoa_r(Param.vmac, buf));
    printf("vip     = %s\n", inet_ntop(AF_INET, &Param.vip, buf, sizeof(buf)));
    printf("vmask   = %s\n", inet_ntop(AF_INET, &Param.vmask, buf, sizeof(buf)));
    printf("gateway = %s\n", inet_ntop(AF_INET, &Param.gateway, buf, sizeof(buf)));
    printf("IpTTL   = %d\n", Param.IpTTL);
    printf("MTU     = %d\n", Param.MTU);
    return 0;
}

int DoCmdEnd() {
    kill(getpid(), SIGTERM);
    return 0;
}

int DoCmd(char *cmd) {
    char *save_ptr;
    char *ptr = strtok_r(cmd, " \r\n", &save_ptr);
    if (ptr == NULL) {
        printf("DoCmd:no cmd\n");
        printf("-----------------------------------------------\n");
        printf("arp -a           : show arp table\n");
        printf("arp -d addr      : delete arp table\n");
        printf("ping addr [size] : send ping\n");
        printf("ifconfig         : show interface configuration\n");
        printf("end              : end program\n");
        printf("-----------------------------------------------\n");
        return -1;
    }

    if (strcmp(ptr, "arp") == 0) {
        DoCmdArp(&save_ptr);
        return 0;
    } else if (strcmp(ptr, "ping") == 0) {
        DoCmdPing(&save_ptr);
        return 0;
    } else if (strcmp(ptr, "ifconfig") == 0) {
        DoCmdIfconfig();
        return 0;
    } else if (strcmp(ptr, "end") == 0) {
        DoCmdEnd();
        return 0;
    } else {
        printf("DoCmd:unknown cmd : %s\n", ptr);
        return -1;
    }
}