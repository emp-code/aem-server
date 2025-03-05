// Require API request timestamps to be within this many milliseconds of the server time
#define AEM_API_TIMEDIFF 5000 // +/- 5 seconds

// Minimum level required to send email
#define AEM_MINLEVEL_SENDEMAIL 2

// Normal address hashing: lower for better performance, higher for better security
//#define AEM_ADDRESS_NOPWHASH // Uncomment to use Siphash for all addresses
#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

// Port numbers
#if defined(AEM_MTA)
	#define AEM_PORT 25
#elif defined(AEM_API_CLR)
	#define AEM_PORT 302
#elif defined(AEM_API_ONI)
	#define AEM_PORT 303
#elif defined(AEM_WEB_CLR)
	#define AEM_PORT 443
#elif defined(AEM_WEB_ONI)
	#define AEM_PORT 880
#elif defined(AEM_MANAGER)
	#define AEM_PORT 940
#endif

#define AEM_PORT_MANAGER_STR "940"

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
