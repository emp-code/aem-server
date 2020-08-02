#ifndef AEM_GLOBAL_H
#define AEM_GLOBAL_H

#define AEM_ACCOUNT_RESPONSE_OK 0
#define AEM_ACCOUNT_RESPONSE_VIOLATION 10

#define AEM_MTA_GETPUBKEY_NORMAL 10
#define AEM_MTA_GETPUBKEY_SHIELD 11
#define AEM_MTA_INSERT 20

#define AEM_DNS_LOOKUP 10

#define AEM_LEN_ACCESSKEY crypto_box_SECRETKEYBYTES
#define AEM_LEN_KEY_MASTER crypto_secretbox_KEYBYTES

#define AEM_LEN_KEY_ACC crypto_box_SECRETKEYBYTES
#define AEM_LEN_KEY_API crypto_box_SECRETKEYBYTES
#define AEM_LEN_KEY_MNG crypto_secretbox_KEYBYTES
#define AEM_LEN_KEY_SIG crypto_sign_SEEDBYTES
#define AEM_LEN_KEY_STI crypto_secretbox_KEYBYTES
#define AEM_LEN_KEY_STO 32 // AES-256
#define AEM_LEN_KEY_DKI 2048 //crypto_sign_SEEDBYTES // RSA/EdDSA

#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

#define AEM_ADDRESSES_PER_USER 31 // (2^5)-1
#define AEM_MINLEVEL_SENDEMAIL 2

#define AEM_LEN_SALT_NORM crypto_pwhash_SALTBYTES
#define AEM_LEN_SALT_SHLD crypto_shorthash_KEYBYTES
#define AEM_LEN_SALT_FAKE crypto_generichash_KEYBYTES
#define AEM_LEN_PRIVATE (4096 - crypto_box_PUBLICKEYBYTES - 1 - (AEM_ADDRESSES_PER_USER * 9))

#define AEM_MAXLEN_ADDR32 16 // 10 bytes Addr32 -> 16 characters
#define AEM_MAXLEN_DOMAIN 32

#define AEM_PORT_MTA 25
#define AEM_PORT_WEB 443
#define AEM_PORT_API 302
#define AEM_PORT_WEB_ONI 880 // Actual port is 80 (HTTP), this is just Tor's localhost port
#define AEM_PORT_MANAGER 940

#define AEM_USERLEVEL_MAX 3
#define AEM_USERLEVEL_MIN 0

#define AEM_EXTMSG_HEADERS_LEN 29
#define AEM_EXTMSG_BODY_MAXLEN ((128 * 1024) - AEM_EXTMSG_HEADERS_LEN - crypto_sign_BYTES - crypto_box_SEALBYTES)
#define AEM_INTMSG_HEADERS_LEN 83

#define AEM_ADDR32_ADMIN  (unsigned char*)"\xa6\xd0\x35\x0e\x75\x85\x68\x18" // 'administrator' in Addr32
#define AEM_ADDR32_SYSTEM (unsigned char*)"\x36\x7d\x9d\x3a\x80\x00\x00\x00\x00\x00" // 'system' in Addr32

#define AEM_SOCKPATH_ACCOUNT "\0AEM_Acc"
#define AEM_SOCKPATH_STORAGE "\0AEM_Sto"
#define AEM_SOCKPATH_ENQUIRY "\0AEM_Enq"
#define AEM_SOCKPATH_LEN 8

#define AEM_MAXLEN_MSGDATA 4194304 // 4 MiB

// Minimum block count: treat zero as this number. Covers overhead, allows larger messages.
// Base: 64 (sig) + 40 (box) = 104
// ExtMsg: 29/133; 44B .. 1M + 59B
// IntMsg: 53/157; 20B .. 1M + 35B
// UplMsg: 46/150; 27B .. 1M + 42B
// 12 * 16 = 192 (-15 --> 177 min)
#define AEM_MSG_MINBLOCKS 12

#define AEM_API_BOX_SIZE_MAX ((UINT16_MAX + AEM_MSG_MINBLOCKS) * 16)
#define AEM_API_SEALBOX_SIZE (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_SEALBYTES)

#define AEM_HOMEDIR "/var/lib/allears"
#define AEM_MOUNTDIR AEM_HOMEDIR"/mount"
#define AEM_MOUNTDIR_FLAGS (MS_NOSUID | MS_NOATIME | MS_SILENT)

#define AEM_BACKLOG 25
#define AEM_TLS_TIMEOUT 30

#define AEM_TIMEOUT_MANAGER_RCV 3
#define AEM_TIMEOUT_MANAGER_SND 3

enum aem_api_commands {
	AEM_API_ACCOUNT_BROWSE,
	AEM_API_ACCOUNT_CREATE,
	AEM_API_ACCOUNT_DELETE,
	AEM_API_ACCOUNT_UPDATE,
	AEM_API_ADDRESS_CREATE,
	AEM_API_ADDRESS_DELETE,
	AEM_API_ADDRESS_LOOKUP,
	AEM_API_ADDRESS_UPDATE,
	AEM_API_MESSAGE_BROWSE,
	AEM_API_MESSAGE_CREATE,
	AEM_API_MESSAGE_DELETE,
	AEM_API_MESSAGE_UPLOAD,
	AEM_API_PRIVATE_UPDATE,
	AEM_API_SETTING_LIMITS,
	AEM_API_INTERNAL_EXIST,
	AEM_API_INTERNAL_LEVEL
};

enum aem_process_types {
	AEM_PROCESSTYPE_MTA,
	AEM_PROCESSTYPE_WEB_CLR,
	AEM_PROCESSTYPE_WEB_ONI,
	AEM_PROCESSTYPE_API_CLR,
	AEM_PROCESSTYPE_API_ONI,
	AEM_PROCESSTYPE_STORAGE,
	AEM_PROCESSTYPE_ACCOUNT,
	AEM_PROCESSTYPE_ENQUIRY,
	AEM_PROCESSTYPES_COUNT
};

// XXX The above and below lists MUST be in the same order

#define AEM_PATH_EXE { \
	AEM_PATH_CONF"/bin/aem-mta", \
	AEM_PATH_CONF"/bin/aem-web-clr", \
	AEM_PATH_CONF"/bin/aem-web-oni", \
	AEM_PATH_CONF"/bin/aem-api-clr", \
	AEM_PATH_CONF"/bin/aem-api-oni", \
	AEM_PATH_CONF"/bin/aem-storage", \
	AEM_PATH_CONF"/bin/aem-account", \
	AEM_PATH_CONF"/bin/aem-enquiry" \
}

#define AEM_NICE { \
	/*MTA*/      -8, \
	/*Web-Clr*/   4, \
	/*Web-Oni*/   8, \
	/*API-Clr*/  -4, \
	/*API-Oni*/  -2, \
	/*Storage*/ -18, \
	/*Account*/ -16, \
	/*Enquiry*/ -18 \
}

#endif
