#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<poll.h>
#include	<sys/ioctl.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/if_ether.h>
#include	<netinet/udp.h>
#include	<netinet/tcp.h>
#include	<linux/if.h>
#include	<arpa/inet.h>
#include	<sys/wait.h>
#include	<pthread.h>
#include	"sock.h"
#include	"ether.h"
#include	"arp.h"
#include	"icmp.h"
#include	"udp.h"
#include	"tcp.h"
#include	"param.h"
#include	"cmd.h"

extern int DeviceSoc;
extern PARAM Param;

int MakeString(char *data) {
    char *tmp = strdup(data);
    char *wp, *rp;

    for (wp = tmp, rp = data; *rp != '\0'; rp++) {
        if (*rp == '\\' && *(rp + 1) != '\0') {
            rp++;
            switch (*rp) {
                case 'n':
                    *wp = '\n';
                    wp++;
                    break;
                case 'r':
                    *wp = '\r';
                    wp++;
                    break;
                case 't':
                    *wp = '\t';
                    wp++;
                    break;
                case '\\':
                    *wp = '\\';
                    wp++;
                    break;
                default:
                    *wp = '\\';
                    wp++;
                    *wp = *rp;
                    wp++;
                    break;
            }
        } else {
            *wp = *rp;
            wp++;
        }
    }
    *wp = '\0';
    strcpy(data, tmp);
    free(tmp);

    return (0);
}

int DoCmdArp(char **cmdline) {
    char *ptr;

    if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
        printf("DoCmdArp:no arg\n");
        return (-1);
    }
    if (strcmp(ptr, "-a") == 0) {
        ArpShowTable();
        return (0);
    } else if (strcmp(ptr, "-d") == 0) {
        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdArp:-d no arg\n");
            return (-1);
        }
        struct in_addr addr;
        inet_aton(ptr, &addr);
        if (ArpDelTable(&addr)) {
            printf("deleted\n");
        } else {
            printf("not exists\n");
        }
        return (0);
    } else {
        printf("DoCmdArp:[%s] unknown\n", ptr);
        return (-1);
    }
}

int DoCmdPing(char **cmdline) {
    char *ptr;
    struct in_addr daddr;
    int size;

    if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
        printf("DoCmdPing:no arg\n");
        return (-1);
    }
    inet_aton(ptr, &daddr);
    if ((ptr = strtok_r(NULL, "\r\n", cmdline)) == NULL) {
        size = DEFAULT_PING_SIZE;
    } else {
        size = atoi(ptr);
    }
    PingSend(DeviceSoc, &daddr, size);

    return (0);
}

int DoCmdIfconfig(char **cmdline) {
    char buf1[80];

    printf("device=%s\n", Param.device);
    printf("vmac=%s\n", my_ether_ntoa_r(Param.vmac, buf1));
    printf("vip=%s\n", inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)));
    printf("vmask=%s\n", inet_ntop(AF_INET, &Param.vmask, buf1, sizeof(buf1)));
    printf("gateway=%s\n", inet_ntop(AF_INET, &Param.gateway, buf1, sizeof(buf1)));
    if (Param.DhcpStartTime == 0) {
        printf("Static\n");
    } else {
        printf("DHCP request lease time=%d\n", Param.DhcpRequestLeaseTime);
        printf("DHCP server=%s\n", inet_ntop(AF_INET, &Param.DhcpServer, buf1, sizeof(buf1)));
        printf("DHCP start time:%s", ctime(&Param.DhcpStartTime));
        printf("DHCP lease time:%d\n", Param.DhcpLeaseTime);
    }
    printf("IpTTL=%d,MTU=%d,MSS=%d\n",Param.IpTTL,Param.MTU,Param.MSS);

    return (0);
}

int DoCmdNetstat(char **cmdline) {
    printf("------------------------------\n");
    printf("proto:no:port=data\n");
    printf("------------------------------\n");
    UdpShowTable();
    TcpShowTable();

    return (0);
}

int DoCmdUdp(char **cmdline) {
    char *ptr;
    u_int16_t port;
    int no, ret;

    if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
        printf("DoCmdUdp:no arg\n");
        return (-1);
    }
    if (strcmp(ptr, "open") == 0) {
        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            no = UdpSocket(0);
        } else {
            port = atoi(ptr);
            no = UdpSocket(port);
        }
        printf("DoCmdUdp:no=%d\n", no);
    } else if (strcmp(ptr, "close") == 0) {
        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdUdp:close:no arg\n");
            return (-1);
        }
        port = atoi(ptr);
        ret = UdpSocketClose(port);
        printf("DoCmdUdp:ret=%d\n", ret);
    } else if (strcmp(ptr, "send") == 0) {
        char *p_addr, *p_port;
        struct in_addr daddr;
        u_int16_t sport, dport;

        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdUdp:send:no arg\n");
            return (-1);
        }
        sport = atoi(ptr);

        if ((p_addr = strtok_r(NULL, ":\r\n", cmdline)) == NULL) {
            printf("DoCmdUdp:send:%u no arg\n", sport);
            return (-1);
        }
        if ((p_port = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdUdp:send:%u %s:no arg\n", sport, p_addr);
            return (-1);
        }
        inet_aton(p_addr, &daddr);
        dport = atoi(p_port);
        if ((ptr = strtok_r(NULL, "\r\n", cmdline)) == NULL) {
            printf("DoCmdUdp:send:%u %s:%d no arg\n", sport, p_addr, dport);
            return (-1);
        }
        MakeString(ptr);
        UdpSend(DeviceSoc, &Param.vip, &daddr, sport, dport, 0, (u_int8_t *) ptr, strlen(ptr));
    } else {
        printf("DoCmdUdp:[%s] unknown\n", ptr);
        return (-1);
    }

    return (0);
}

int DoCmdTcp(char **cmdline) {
    char *ptr;
    u_int16_t port;
    int no, ret;

    if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
        printf("DoCmdTcp:no arg\n");
        return (-1);
    }
    if (strcmp(ptr, "listen") == 0) {
        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            no = TcpSocketListen(0);
        } else {
            port = atoi(ptr);
            no = TcpSocketListen(port);
        }
        printf("DoCmdTcp:no=%d\n", no);
    } else if (strcmp(ptr, "close") == 0) {
        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdTcp:close:no arg\n");
            return (-1);
        }
        port = atoi(ptr);
        ret = TcpClose(DeviceSoc, port);
        printf("DoCmdTcp:ret=%d\n", ret);
    } else if (strcmp(ptr, "reset") == 0) {
        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdTcp:reset:no arg\n");
            return (-1);
        }
        port = atoi(ptr);
        ret = TcpReset(DeviceSoc, port);
        printf("DoCmdTcp:ret=%d\n", ret);
    } else if (strcmp(ptr, "connect") == 0) {
        char *p_addr, *p_port;
        struct in_addr daddr;
        u_int16_t sport, dport;

        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdTcp:connect:no arg\n");
            return (-1);
        }
        sport = atoi(ptr);

        if ((p_addr = strtok_r(NULL, ":\r\n", cmdline)) == NULL) {
            printf("DoCmdTcp:connect:%u no arg\n", sport);
            return (-1);
        }
        if ((p_port = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdTcp:connect:%u %s:no arg\n", sport, p_addr);
            return (-1);
        }
        inet_aton(p_addr, &daddr);
        dport = atoi(p_port);
        TcpConnect(DeviceSoc, sport, &daddr, dport);
    } else if (strcmp(ptr, "send") == 0) {
        u_int16_t sport;

        if ((ptr = strtok_r(NULL, " \r\n", cmdline)) == NULL) {
            printf("DoCmdTcp:send:no arg\n");
            return (-1);
        }
        sport = atoi(ptr);

        if ((ptr = strtok_r(NULL, "\r\n", cmdline)) == NULL) {
            printf("DoCmdTcp:send:%u no arg\n", sport);
            return (-1);
        }
        MakeString(ptr);
        TcpSend(DeviceSoc, sport, (u_int8_t *) ptr, strlen(ptr));
    } else {
        printf("DoCmdTcp:[%s] unknown\n", ptr);
        return (-1);
    }

    return (0);
}

int DoCmdEnd(char **cmdline) {
    kill(getpid(), SIGTERM);

    return (0);
}

int DoCmd(char *cmd) {
    char *ptr, *saveptr;

    if ((ptr = strtok_r(cmd, " \r\n", &saveptr)) == NULL) {
        printf("DoCmd:no cmd\n");
        printf("---------------------------------------\n");
        printf("arp -a : show arp table\n");
        printf("arp -d addr : del arp table\n");
        printf("ping addr [size] : send ping\n");
        printf("ifconfig : show interface configuration\n");
        printf("netstat : show active ports\n");
        printf("udp open port : open udp-recv port\n");
        printf("udp close port : close udp-recv port\n");
        printf("udp send sport daddr:dport data : send udp\n");
        printf("tcp listen port : listen tcp-accept port\n");
        printf("tcp close port : close tcp port\n");
        printf("tcp reset port : reset tcp port\n");
        printf("tcp connect sport daddr:dport : tcp connect\n");
        printf("tcp send sport data : send tcp\n");
        printf("end : end program\n");
        printf("---------------------------------------\n");
        return (-1);
    }

    if (strcmp(ptr, "arp") == 0) {
        DoCmdArp(&saveptr);
        return (0);
    } else if (strcmp(ptr, "ping") == 0) {
        DoCmdPing(&saveptr);
        return (0);
    } else if (strcmp(ptr, "ifconfig") == 0) {
        DoCmdIfconfig(&saveptr);
        return (0);
    } else if (strcmp(ptr, "netstat") == 0) {
        DoCmdNetstat(&saveptr);
        return (0);
    } else if (strcmp(ptr, "udp") == 0) {
        DoCmdUdp(&saveptr);
        return (0);
    } else if (strcmp(ptr, "tcp") == 0) {
        DoCmdTcp(&saveptr);
        return (0);
    } else if (strcmp(ptr, "end") == 0) {
        DoCmdEnd(&saveptr);
        return (0);
    } else {
        printf("DoCmd:unknown cmd : %s\n", ptr);
        return (-1);
    }
}