#define	DHCP_SERVER_PORT	(67)
#define	DHCP_CLIENT_PORT	(68)

#define DHCP_UDP_OVERHEAD	(14 + /* Ethernet header */	\
				 20 + /* IP header */		\
				 8)   /* UDP header */
#define DHCP_SNAME_LEN		64
#define DHCP_FILE_LEN		128
#define DHCP_FIXED_NON_UDP	236
#define DHCP_FIXED_LEN		(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
#define DHCP_MTU_MAX		1500
#define DHCP_OPTION_LEN		(DHCP_MTU_MAX - DHCP_FIXED_LEN)

struct dhcp_packet {
    u_int8_t op;        /* 0: Message opcode/type */
    u_int8_t htype;    /* 1: Hardware addr type (net/if_types.h) */
    u_int8_t hlen;        /* 2: Hardware addr length */
    u_int8_t hops;        /* 3: Number of relay agent hops from client */
    u_int32_t xid;        /* 4: Transaction ID */
    u_int16_t secs;        /* 8: Seconds since client started looking */
    u_int16_t flags;    /* 10: Flag bits */
    struct in_addr ciaddr;  /* 12: Client IP address (if already in use) */
    struct in_addr yiaddr;  /* 16: Client IP address */
    struct in_addr siaddr;  /* 18: IP address of next server to talk to */
    struct in_addr giaddr;  /* 20: DHCP relay agent IP address */
    u_int8_t chaddr[16];    /* 24: Client hardware address */
    char sname[DHCP_SNAME_LEN];    /* 40: Server name */
    char file[DHCP_FILE_LEN];    /* 104: Boot filename */
    u_int8_t options[DHCP_OPTION_LEN];
    /* 212: Optional parameters (actual length dependent on MTU). */
};

#define BOOTREQUEST	1
#define BOOTREPLY	2

#define HTYPE_ETHER	  1	/* Ethernet 10Mbps		*/
#define HTYPE_IEEE802 6	/* IEEE 802.2 Token Ring...	*/
#define HTYPE_FDDI    8	/* FDDI...			*/

#define DHCP_OPTIONS_COOKIE	"\143\202\123\143"

#define DHCPDISCOVER 1
#define DHCPOFFER	 2
#define DHCPREQUEST	 3
#define DHCPDECLINE	 4
#define DHCPACK		 5
#define DHCPNAK		 6
#define DHCPRELEASE	 7
#define DHCPINFORM	 8

#define OPTION_STR_MAX 64

typedef struct {
    int no;
    char kind;
    char *data;
    int len;
} OPTION;

int print_dhcp(struct dhcp_packet *pa,int size);
u_int8_t *dhcp_set_option(u_int8_t *ptr,int tag,int size,u_int8_t *buf);
int dhcp_get_option(struct dhcp_packet *pa,int size,int opno,void *val);
int MakeDhcpRequest(struct dhcp_packet *pa,u_int8_t mtype,struct in_addr *ciaddr,struct in_addr *req_ip,struct in_addr *server);
int DhcpSendDiscover(int soc);
int DhcpSendRequest(int soc,struct in_addr *yiaddr,struct in_addr *server);
int DhcpSendRequestUni(int soc);
int DhcpSendRelease(int soc);
int DhcpRecv(int soc,u_int8_t *data,int len,struct ether_header *eh,struct ip *ip,struct udphdr *udp);
int DhcpCheck(int soc);
