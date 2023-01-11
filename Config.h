// Minimum level required to send email
#define AEM_MINLEVEL_SENDEMAIL 2

// Normal address hashing: lower for better performance, higher for better security
#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

// Port numbers
#if defined(AEM_MTA)
	#define AEM_PORT 25
#elif defined(AEM_API)
	#define AEM_PORT 302
#elif defined(AEM_WEB)
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
#define AEM_TLS_TIMEOUT 30
#define AEM_API_TIMEOUT 5

// Misc
#define AEM_MAXLEN_MSGDATA 1048752 // Minimum: 1048752; 176 bytes over 1 MiB; ((2^16 - 1) + 12) * 16
#define AEM_MAXUSERS 9999
