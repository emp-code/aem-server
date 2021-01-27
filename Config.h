// Minimum level required to send email
#define AEM_MINLEVEL_SENDEMAIL 2

// Normal address hashing: lower for better performance, higher for better security
#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

// Port numbers
#define AEM_PORT_MTA 25
#define AEM_PORT_WEB 443
#define AEM_PORT_API 302
#define AEM_PORT_WEB_ONI 880 // Actual port is 80 (HTTP), this is just Tor's localhost port
#define AEM_PORT_MANAGER 940
#define AEM_PORT_MANAGER_STR "940"
