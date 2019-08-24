
#define DEFAULT_MTU ETHERMTU
#define DEFAULT_IP_TTL 64
#define	DEFAULT_PING_SIZE 64
#define	DUMMY_WAIT_MS 100
#define	RETRY_COUNT	3

typedef struct {
    char *device;
    int mymac[6];
    struct in_addr myip;
    int vmac[6];
    struct in_addr vip;
    struct in_addr vmask;
    struct in_addr gateway;
    int IpTTL;
    int MTU;
} PARAM;

void SetDefaultParam();
int ReadParam(char *filename);
int isTargetIPAddr(struct in_addr *addr);
int isSameSubnet(struct in_addr *addr);