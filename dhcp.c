#include	<stdio.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<sys/ioctl.h>
#include	<netpacket/packet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/udp.h>
#include	<linux/if.h>
#include	<arpa/inet.h>
#include	"sock.h"
#include	"ether.h"
#include	"arp.h"
#include	"ip.h"
#include	"udp.h"
#include	"dhcp.h"
#include	"param.h"

extern PARAM Param;
extern u_int8_t	BcastMac[6];

int print_dhcp(struct dhcp_packet *pa,int size) {
    int i;
    char cookie[4];
    u_int8_t *ptr;
    struct in_addr addr;
    u_int32_t l;
    u_int16_t s;
    int end, n;
    char buf[512], buf1[80];

    printf("dhcp----------------------------------------------------------------------------\n");

    printf("op=%d:", pa->op);
    if (pa->op == BOOTREQUEST) {
        printf("BOOTREQUEST\n");
    } else if (pa->op == BOOTREPLY) {
        printf("BOOTREPLY\n");
    } else {
        printf("UNDEFINE\n");
        return (-1);
    }

    printf("htype=%d:", pa->htype);
    if (pa->htype == HTYPE_ETHER) {
        printf("HTYPE_ETHER\n");
    } else if (pa->htype == HTYPE_IEEE802) {
        printf("HTYPE_IEEE802\n");
    } else {
        printf("UNDEFINE\n");
        return (-1);
    }

    printf("hlen=%d\n", pa->hlen);

    printf("hops=%d\n", pa->hops);

    printf("xid=%u\n", pa->xid);

    printf("secs=%d\n", pa->secs);

    printf("flags=%x\n", pa->flags);

    printf("ciaddr=%s\n", inet_ntop(AF_INET, &pa->ciaddr, buf1, sizeof(buf1)));

    printf("yiaddr=%s\n", inet_ntop(AF_INET, &pa->yiaddr, buf1, sizeof(buf1)));

    printf("siaddr=%s\n", inet_ntop(AF_INET, &pa->siaddr, buf1, sizeof(buf1)));

    printf("giaddr=%s\n", inet_ntop(AF_INET, &pa->giaddr, buf1, sizeof(buf1)));

    printf("chaddr=%s\n", my_ether_ntoa_r(pa->chaddr, buf1));

    printf("sname=%s\n", pa->sname);

    printf("file=%s\n", pa->file);

    printf("options\n");

    ptr = pa->options;
    memcpy(cookie, ptr, 4);
    ptr += 4;
    if (memcmp(cookie, DHCP_OPTIONS_COOKIE, 4) != 0) {
        printf("options:cookie:error\n");
        return (-1);
    }

    end = 0;
    while (ptr < (u_int8_t *) pa + size) {
        switch (*ptr) {
            case 0:
                printf("0:pad\n");
                ptr++;
                break;
            case 1:
                printf("1:subnet mask:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&addr, ptr, 4);
                ptr += 4;
                printf("%s\n", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                break;
            case 2:
                printf("2:time offset:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&l, ptr, 4);
                ptr += 4;
                printf("%d\n", ntohl(l));
                break;
            case 255:
                printf("255:end\n");
                end = 1;
                break;
            case 3:
                printf("3:router(gateway):");
                ptr++;
                goto IP;
            case 4:
                printf("4:time server:");
                ptr++;
                goto IP;
            case 5:
                printf("5:IEN-116 name server:");
                ptr++;
                goto IP;
            case 6:
                printf("6:domain name server:");
                ptr++;
                goto IP;
            case 7:
                printf("7:log name server:");
                ptr++;
                goto IP;
            case 8:
                printf("8:cookie/quote name server:");
                ptr++;
                goto IP;
            case 9:
                printf("9:lpr name server:");
                ptr++;
                goto IP;
            case 10:
                printf("10:impress name server:");
                ptr++;
                goto IP;
            case 11:
                printf("11:rlp name server:");
                ptr++;
            IP:
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 12:
                printf("12:hostname:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 13:
                printf("13:boot file size:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&s, ptr, 2);
                ptr += 2;
                printf("%d\n", ntohs(s));
                break;
            case 14:
                printf("14:merit dump file:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 15:
                printf("15:domain name:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 16:
                printf("16:swap server:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&addr, ptr, 4);
                ptr += 4;
                printf("%s\n", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                break;
            case 17:
                printf("17:root path:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 18:
                printf("18:extensions path:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 19:
                printf("19:ip forwarding:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 20:
                printf("20:non-local source routing:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 21:
                printf("21:policy filter:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 22:
                printf("22:maximum datagram reassembly size:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&s, ptr, 2);
                ptr += 2;
                printf("%d\n", ntohs(s));
                break;
            case 23:
                printf("23:default ip time-to-live:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 24:
                printf("24:path MTU aging timeout:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&l, ptr, 4);
                ptr += 4;
                printf("%d\n", ntohl(l));
                break;
            case 25:
                printf("25:path MTU plateau table:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 26:
                printf("26:interface MTU:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&s, ptr, 2);
                ptr += 2;
                printf("%d\n", ntohs(s));
                break;
            case 27:
                printf("27:all subnets are local:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 28:
                printf("28:broadcast address:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&addr, ptr, 4);
                ptr += 4;
                printf("%s\n", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                break;
            case 29:
                printf("29:perform mask discovery:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 30:
                printf("30:mask supplier:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 31:
                printf("31:perform router discovery:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 32:
                printf("32:router solicitation address:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&addr, ptr, 4);
                ptr += 4;
                printf("%s\n", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                break;
            case 33:
                printf("33:static route:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 34:
                printf("34:trailer encapsulation:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 35:
                printf("35:ARP cache timeout:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&l, ptr, 4);
                ptr += 4;
                printf("%d\n", ntohl(l));
                break;
            case 36:
                printf("36:ethernet encapsulation:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 37:
                printf("37:TCP default TTL:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 38:
                printf("38:TCP keepalive interval:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&l, ptr, 4);
                ptr += 4;
                printf("%d\n", ntohl(l));
                break;
            case 39:
                printf("37:TCP keepalive garbage:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 40:
                printf("40:network information service domain:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 41:
                printf("41:network information servers:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 42:
                printf("42:network time protocol servers:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 43:
                printf("43:vendor specific information:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n; i++) {
                    if (i != 0) {
                        printf(":");
                    }
                    printf("%02X", (*ptr) & 0xFF);
                    ptr++;
                }
                printf("\n");
                break;
            case 44:
                printf("44:NetBIOS over TCP/IP name server:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 45:
                printf("45:NetBIOS over TCP/IP datagram distribution server:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 46:
                printf("46:NetBIOS over TCP/IP node type:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%x\n", *ptr);
                ptr++;
                break;
            case 47:
                printf("47:NetBIOS over TCP/IP scope:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 48:
                printf("48:X window system font server:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 49:
                printf("49:X window system display manager:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n / 4; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    memcpy(&addr, ptr, 4);
                    ptr += 4;
                    printf("%s", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                }
                printf("\n");
                break;
            case 50:
                printf("50:requested IP address:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&addr, ptr, 4);
                ptr += 4;
                printf("%s\n", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                break;
            case 51:
                printf("51:IP address lease time:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&l, ptr, 4);
                ptr += 4;
                printf("%d\n", ntohl(l));
                break;
            case 52:
                printf("52:option overload:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d\n", *ptr);
                ptr++;
                break;
            case 53:
                printf("53:DHCP message type:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                printf("%d:", *ptr);
                if (*ptr == DHCPDISCOVER) {
                    printf("DHCPDISCOVER\n");
                } else if (*ptr == DHCPOFFER) {
                    printf("DHCPOFFER\n");
                } else if (*ptr == DHCPREQUEST) {
                    printf("DHCPREQUEST\n");
                } else if (*ptr == DHCPDECLINE) {
                    printf("DHCPDECLINE\n");
                } else if (*ptr == DHCPACK) {
                    printf("DHCPACK\n");
                } else if (*ptr == DHCPNAK) {
                    printf("DHCPNAK\n");
                } else if (*ptr == DHCPRELEASE) {
                    printf("DHCPRELEASE\n");
                } else if (*ptr == DHCPINFORM) {
                    printf("DHCPINFORM\n");
                } else {
                    printf("UNDEFINE\n");
                }
                ptr++;
                break;
            case 54:
                printf("54:server identifier:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&addr, ptr, 4);
                ptr += 4;
                printf("%s\n", inet_ntop(AF_INET, &addr, buf1, sizeof(buf1)));
                break;
            case 55:
                printf("55:parameter request list:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n; i++) {
                    if (i != 0) {
                        printf(",");
                    }
                    printf("%d", *ptr);
                    ptr++;
                }
                printf("\n");
                break;
            case 56:
                printf("56:message:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 57:
                printf("57:maximum DHCP message size:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&s, ptr, 2);
                ptr += 2;
                printf("%d\n", ntohs(s));
                break;
            case 58:
                printf("58:renewal (T1) time value:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&l, ptr, 4);
                ptr += 4;
                printf("%d\n", ntohl(l));
                break;
            case 59:
                printf("59:rebinding (T1) time value:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                memcpy(&l, ptr, 4);
                ptr += 4;
                printf("%d\n", ntohl(l));
                break;
            case 60:
                printf("60:class-identifier:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                if (n >= 512) {
                    memcpy(buf, ptr, 511);
                    buf[511] = '\0';
                } else {
                    memcpy(buf, ptr, n);
                    buf[n] = '\0';
                }
                ptr += n;
                printf("%s\n", buf);
                break;
            case 61:
                printf("61:client-identifier:");
                ptr++;
                n = *ptr;
                ptr++;
                printf("%d:", n);
                for (i = 0; i < n; i++) {
                    if (i != 0) {
                        printf(":");
                    }
                    printf("%02X", (*ptr) & 0xFF);
                    ptr++;
                }
                printf("\n");
                break;
            default:
                if (*ptr >= 128 && *ptr <= 254) {
                    printf("%d:reserved fields:", *ptr);
                    ptr++;
                    n = *ptr;
                    ptr++;
                    printf("%d:", n);
                    for (i = 0; i < n; i++) {
                        if (i != 0) {
                            printf(":");
                        }
                        printf("%02X", (*ptr) & 0xFF);
                        ptr++;
                    }
                    printf("\n");
                } else {
                    printf("%d:undefined:", *ptr);
                    ptr++;
                    n = *ptr;
                    ptr++;
                    printf("%d:", n);
                    for (i = 0; i < n; i++) {
                        if (i != 0) {
                            printf(":");
                        }
                        printf("%02X", (*ptr) & 0xFF);
                        ptr++;
                    }
                    printf("\n");
                }
                break;
        }
        if (end) {
            break;
        }
    }

    return (0);
}

u_int8_t *dhcp_set_option(u_int8_t *ptr,int tag,int size,u_int8_t *buf) {
    *ptr = (u_int8_t) tag;
    ptr++;
    if (size > 255) {
        size = 255;
    }
    *ptr = (u_int8_t) size;
    ptr++;
    memcpy(ptr, buf, size);
    ptr += size;

    return (ptr);
}

int dhcp_get_option(struct dhcp_packet *pa,int size,int opno,void *val) {
    u_int8_t cookie[4];
    u_int8_t *ptr;
    int end, n;

    ptr = pa->options;
    memcpy(cookie, ptr, 4);
    ptr += 4;
    if (memcmp(cookie, DHCP_OPTIONS_COOKIE, 4) != 0) {
        printf("analize_packet:options:cookie:error\n");
        return (-1);
    }

    end = 0;
    while (ptr < (u_int8_t *) pa + size) {
        if (*ptr == 0) {
            ptr++;
        } else if (*ptr == 255) {
            end = 1;
        } else if (*ptr == opno) {
            ptr++;
            n = *ptr;
            ptr++;
            memcpy(val, ptr, n);
            ptr += n;
            end = 1;
        } else {
            ptr++;
            n = *ptr;
            ptr++;
            ptr += n;
        }
        if (end) {
            break;
        }
    }

    return (0);
}

int MakeDhcpRequest(struct dhcp_packet *pa,u_int8_t mtype,struct in_addr *ciaddr,struct in_addr *req_ip,struct in_addr *server) {
    u_int8_t *ptr;
    u_int8_t buf[512];
    int size;
    u_int32_t l;

    memset(pa, 0, sizeof(struct dhcp_packet));
    pa->op = BOOTREQUEST;
    pa->htype = HTYPE_ETHER;
    pa->hlen = 6;
    pa->hops = 0;
    pa->xid = htons(getpid() & 0xFFFF);
    pa->secs = 0;
    pa->flags = htons(0x8000);

    if (ciaddr == NULL) {
        pa->ciaddr.s_addr = 0;
    } else {
        pa->ciaddr.s_addr = ciaddr->s_addr;
    }
    pa->yiaddr.s_addr = 0;
    pa->siaddr.s_addr = 0;
    pa->giaddr.s_addr = 0;
    memcpy(pa->chaddr, Param.vmac, 6);
    strcpy(pa->sname, "");
    strcpy(pa->file, "");

    ptr = pa->options;
    memcpy(ptr, DHCP_OPTIONS_COOKIE, 4);
    ptr += 4;

    buf[0] = mtype;
    ptr = dhcp_set_option(ptr, 53, 1, buf);

    l = htonl(Param.DhcpRequestLeaseTime);
    ptr = dhcp_set_option(ptr, 51, 4, (u_int8_t * ) & l);

    if (req_ip != NULL) {
        ptr = dhcp_set_option(ptr, 50, 4, (u_int8_t * ) & req_ip->s_addr);
    }

    if (server != NULL) {
        ptr = dhcp_set_option(ptr, 54, 4, (u_int8_t * ) & server->s_addr);
    }

    buf[0] = 1;
    buf[1] = 3;
    ptr = dhcp_set_option(ptr, 55, 2, buf);

    ptr = dhcp_set_option(ptr, 255, 0, NULL);

    size = ptr - (u_int8_t *) pa;

    return (size);
}

int DhcpSendDiscover(int soc) {
    int size;
    struct dhcp_packet pa;
    struct in_addr saddr, daddr;

    saddr.s_addr = 0;
    inet_aton("255.255.255.255", &daddr);

    size = MakeDhcpRequest(&pa, DHCPDISCOVER, NULL, NULL, NULL);

    printf("--- DHCP ---{\n");
    UdpSendLink(soc, Param.vmac, BcastMac, &saddr, &daddr, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, 1, (u_int8_t * ) & pa,
                size);
    print_dhcp(&pa, size);
    printf("}\n");

    return (0);
}

int DhcpSendRequest(int soc,struct in_addr *yiaddr,struct in_addr *server) {
    int size;
    struct dhcp_packet pa;
    struct in_addr saddr, daddr;

    saddr.s_addr = 0;
    inet_aton("255.255.255.255", &daddr);

    size = MakeDhcpRequest(&pa, DHCPREQUEST, NULL, yiaddr, server);

    printf("--- DHCP ---{\n");
    UdpSendLink(soc, Param.vmac, BcastMac, &saddr, &daddr, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, 1, (u_int8_t * ) & pa,
                size);
    print_dhcp(&pa, size);
    printf("}\n");

    return (0);
}

int DhcpSendRequestUni(int soc) {
    int size;
    struct dhcp_packet pa;

    size = MakeDhcpRequest(&pa, DHCPREQUEST, &Param.vip, &Param.vip, &Param.DhcpServer);

    printf("--- DHCP ---{\n");
    UdpSend(soc, &Param.vip, &Param.DhcpServer, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, 1, (u_int8_t * ) & pa, size);
    print_dhcp(&pa, size);
    printf("}\n");

    return (0);
}

int DhcpSendRelease(int soc) {
    int size;
    struct dhcp_packet pa;

    size = MakeDhcpRequest(&pa, DHCPRELEASE, &Param.vip, NULL, &Param.DhcpServer);

    printf("--- DHCP ---{\n");
    UdpSend(soc, &Param.vip, &Param.DhcpServer, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, 1, (u_int8_t * ) & pa, size);
    print_dhcp(&pa, size);
    printf("}\n");

    return (0);
}

int DhcpRecv(int soc,u_int8_t *data,int len,struct ether_header *eh,struct ip *ip,struct udphdr *udp) {
    char buf1[80];
    struct dhcp_packet *ppa;
    struct in_addr server;

    ppa = (struct dhcp_packet *) data;
    if (memcmp(ppa->chaddr, Param.vmac, 6) != 0) {
        return (-1);
    }
    if (ntohs(ppa->xid) != (getpid() & 0xFFFF)) {
        printf("DhcpRecv:xid not match(%x:%x)\n", ntohs(ppa->xid), getpid() & 0xFFFF);
        return (-1);
    }

    printf("--- recv ---[\n");
    print_ether_header(eh);
    print_ip(ip);
    print_udp(udp);
    print_dhcp(ppa, len);
    printf("]\n");

    if (ppa->op == BOOTREPLY) {
        u_int8_t type;
        dhcp_get_option(ppa, len, 53, &type);
        if (type == DHCPOFFER) {
            dhcp_get_option(ppa, len, 54, &server.s_addr);
            DhcpSendRequest(soc, &ppa->yiaddr, &server);
        } else if (type == DHCPACK) {
            Param.vip.s_addr = ppa->yiaddr.s_addr;
            dhcp_get_option(ppa, len, 54, &Param.DhcpServer.s_addr);
            dhcp_get_option(ppa, len, 1, &Param.vmask);
            dhcp_get_option(ppa, len, 3, &Param.gateway);
            dhcp_get_option(ppa, len, 51, &Param.DhcpLeaseTime);
            Param.DhcpLeaseTime = ntohl(Param.DhcpLeaseTime);
            Param.DhcpStartTime = time(NULL);
            printf("vip=%s\n", inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)));
            printf("vmask=%s\n", inet_ntop(AF_INET, &Param.vmask, buf1, sizeof(buf1)));
            printf("gateway=%s\n", inet_ntop(AF_INET, &Param.gateway, buf1, sizeof(buf1)));
            printf("DHCP server=%s\n", inet_ntop(AF_INET, &Param.DhcpServer, buf1, sizeof(buf1)));
            printf("DHCP start time=%s", ctime_r(&Param.DhcpStartTime, buf1));
            printf("DHCP lease time=%d\n", Param.DhcpLeaseTime);
        } else if (type == DHCPNAK) {
            Param.vip.s_addr = 0;
            Param.vmask.s_addr = 0;
            Param.gateway.s_addr = 0;
            Param.DhcpServer.s_addr = 0;
            Param.DhcpStartTime = 0;
            Param.DhcpLeaseTime = 0;
            DhcpSendDiscover(soc);
        }
    }

    return (0);
}

int DhcpCheck(int soc) {
    if (time(NULL) - Param.DhcpStartTime >= Param.DhcpLeaseTime / 2) {
        Param.DhcpStartTime += Param.DhcpLeaseTime / 2;
        Param.DhcpLeaseTime /= 2;
        if (DhcpSendRequestUni(soc) == -1) {
            printf("DhcpCheck:DhcpSendRequestUni:error\n");
            Param.vip.s_addr = 0;
            Param.vmask.s_addr = 0;
            Param.gateway.s_addr = 0;
            Param.DhcpServer.s_addr = 0;
            Param.DhcpStartTime = 0;
            Param.DhcpLeaseTime = 0;
            DhcpSendDiscover(soc);
        }
    }
    if (time(NULL) - Param.DhcpStartTime >= Param.DhcpLeaseTime) {
        printf("DhcpCheck:lease timeout\n");
        Param.vip.s_addr = 0;
        Param.vmask.s_addr = 0;
        Param.gateway.s_addr = 0;
        Param.DhcpServer.s_addr = 0;
        Param.DhcpStartTime = 0;
        Param.DhcpLeaseTime = 0;
        DhcpSendDiscover(soc);
    }

    return (0);
}