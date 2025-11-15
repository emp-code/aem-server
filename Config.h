// Require API request timestamps to be within this many milliseconds of the server time
#define AEM_API_TIMEDIFF 5000 // +/- 5 seconds
#define AEM_API_TIMEDIFF_UPL 60000 // +/- 60 seconds, for file uploads
#define AEM_API_TIMEDIFF_REG 5000 // +/- 5 seconds, for user registrations

// Minimum level required to send email
#define AEM_MINLEVEL_SENDEMAIL 2

#define AEM_LIMITS_DEFAULT \
/* MiB, Nrm, Shd */ \
/* Lv. 0 */ {0, 0, 0}, \
/* Lv. 1 */ {0, 0, 0}, \
/* Lv. 2 */ {0, 0, 0}, \
/* Admin */ {UINT8_MAX, AEM_ADDRESSES_PER_USER, AEM_ADDRESSES_PER_USER}

// Welcome message
#define AEM_WELCOME_MAXLEN 4096 // 4 KiB
#define AEM_WELCOME_DEFAULT "Welcome to All-Ears Mail\nThis is the default welcome message for All-Ears Mail."

// Admin-only addresses
#define AEM_ADMIN_ADDR_MAX 8192 // 8192*8 = 64 KiB
#define AEM_ADMIN_ADDR_DEFAULT (unsigned char[]){\
0x2a,0x97,0xbc,0xb8,0x00,0x00,0x00,0x00,0x00,0x00 /*abuse*/,\
0x2a,0x9b,0x40,0xd4,0x00,0x00,0x00,0x00,0x00,0x00 /*admin*/,\
0x6a,0x9b,0x40,0xd4,0x39,0xd6,0x15,0xa0,0x60,0x00 /*administrator*/,\
0x24,0x5c,0x1b,0x00,0x00,0x00,0x00,0x00,0x00,0x00 /*help*/,\
0x54,0x41,0x9d,0x51,0x59,0xd3,0xb0,0x00,0x00,0x00 /*hostmaster*/,\
0x20,0x6a,0xf0,0x00,0x00,0x00,0x00,0x00,0x00,0x00 /*info*/,\
0x55,0x81,0x9d,0x51,0x59,0xd3,0xb0,0x00,0x00,0x00 /*postmaster*/,\
0x46,0x5c,0xcd,0xe0,0x3a,0xf0,0x00,0x00,0x00,0x00 /*security*/,\
0x3e,0x77,0x6b,0x03,0x1a,0x00,0x00,0x00,0x00,0x00 /*support*/,\
0x4f,0x1c,0xba,0x2b,0x3a,0x76,0x00,0x00,0x00,0x00 /*webmaster*/}
#define AEM_ADMIN_ADDR_DEFAULT_COUNT 10

// Normal address hashing: lower for better performance, higher for better security
//#define AEM_ADDRESS_NOPWHASH // Uncomment to use Siphash for all addresses
#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

// Port numbers
#if defined(AEM_MTA)
	#define AEM_PORT 25 // SMTP
#endif

// UDS paths
#ifdef AEM_API
	#define AEM_UDS_HEX (unsigned char[]){'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'}
	#define AEM_UDS_PATH (char[]){'\0','A','E','M','_','A','P','I','_', AEM_UDS_HEX[udsId >> 4], AEM_UDS_HEX[udsId % 15]}
	#define AEM_UDS_PATH_LEN 11
#elifdef AEM_WEB
	#define AEM_UDS_PATH (char[]){'\0','A','E','M','_','W','e','b'}
	#define AEM_UDS_PATH_LEN 8
#elifdef AEM_REG
	#define AEM_UDS_PATH (char[]){'\0','A','E','M','_','R','e','g'}
	#define AEM_UDS_PATH_LEN 8
#elifdef AEM_MANAGER
	#define AEM_UDS_PATH (char[]){'\0','A','E','M','_','M','n','g'}
	#define AEM_UDS_PATH_LEN 8
#endif

// DNS
#define AEM_DNS_SERVER_ADDR "9.9.9.10" // Quad9 non-filtering | https://quad9.net
#define AEM_DNS_SERVER_PORT 53

// DNSBL; see https://en.wikipedia.org/wiki/Comparison_of_DNS_blacklists
#define AEM_MTA_DNSBL_LEN 15
#define AEM_MTA_DNSBL "dnsbl.sorbs.net"

// Network
#define AEM_BACKLOG 25

// Misc
#define AEM_USER_SIZE 8192 // Size of each of the 4096 users. Determines the size of the Private field. 8 KiB * 4096 = 32 MiB.
