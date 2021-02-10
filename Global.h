#ifndef AEM_GLOBAL_H
#define AEM_GLOBAL_H

#include "Config.h"

enum aem_internal_response {
	AEM_INTERNAL_RESPONSE_NONE,
	AEM_INTERNAL_RESPONSE_OK,
	AEM_INTERNAL_RESPONSE_ERR,
	AEM_INTERNAL_RESPONSE_VIOLATION
};

#define AEM_MTA_ADREXISTS_SHIELD 5
#define AEM_MTA_GETPUBKEY_NORMAL 10
#define AEM_MTA_GETPUBKEY_SHIELD 11
#define AEM_MTA_INSERT 20

enum aem_internal_enquiry {
	AEM_ENQUIRY_MX,
	AEM_ENQUIRY_IP,
};

#define AEM_LEN_KEY_MASTER crypto_secretbox_KEYBYTES

#define AEM_LEN_KEY_ACC crypto_secretbox_KEYBYTES
#define AEM_LEN_KEY_API crypto_box_SECRETKEYBYTES
#define AEM_LEN_KEY_MNG crypto_secretbox_KEYBYTES
#define AEM_LEN_KEY_SIG crypto_sign_SEEDBYTES
#define AEM_LEN_KEY_STI crypto_secretbox_KEYBYTES
#define AEM_LEN_KEY_STO 32 // AES-256

#define AEM_PATH_CONF "/etc/allears"

#define AEM_PATH_KEY_MNG AEM_PATH_CONF"/Manager.key"
#define AEM_PATH_KEY_ACC AEM_PATH_CONF"/Account.key"
#define AEM_PATH_KEY_API AEM_PATH_CONF"/API.key"
#define AEM_PATH_KEY_MNG AEM_PATH_CONF"/Manager.key"
#define AEM_PATH_KEY_SIG AEM_PATH_CONF"/Signing.key"
#define AEM_PATH_KEY_STO AEM_PATH_CONF"/Storage.key"
#define AEM_PATH_SLT_SHD AEM_PATH_CONF"/Shield.slt"

#define AEM_ADDRESSES_PER_USER 31 // (2^5)-1

#define AEM_LEN_SLT_NRM crypto_pwhash_SALTBYTES
#define AEM_LEN_SLT_SHD crypto_shorthash_KEYBYTES
#define AEM_LEN_PRIVATE (4096 - crypto_box_PUBLICKEYBYTES - 1 - (AEM_ADDRESSES_PER_USER * 9))

#define AEM_MAXLEN_ADDR32 16 // 10 bytes Addr32 -> 16 characters
#define AEM_MAXNUM_ATTACHMENTS 31

#define AEM_MAXPROCESSES 100
#define AEM_MANAGER_RESLEN_DECRYPTED (AEM_MAXPROCESSES * 5 * 4)
#define AEM_MANAGER_RESLEN_ENCRYPTED (AEM_MANAGER_RESLEN_DECRYPTED + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define AEM_MANAGER_CMDLEN_DECRYPTED 6
#define AEM_MANAGER_CMDLEN_ENCRYPTED (AEM_MANAGER_CMDLEN_DECRYPTED + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)

#define AEM_USERLEVEL_MAX 3
#define AEM_USERLEVEL_MIN 0

#define AEM_EXTMSG_HEADERS_LEN 29
#define AEM_EXTMSG_BODY_MAXLEN ((128 * 1024) - AEM_EXTMSG_HEADERS_LEN - crypto_sign_BYTES - crypto_box_SEALBYTES)

#define AEM_ADDR32_ADMIN  (const unsigned char[]) {'\xa6', '\xd0', '\x35', '\x0e', '\x75', '\x85', '\x68', '\x18'} // 'administrator' in Addr32
#define AEM_ADDR32_SYSTEM (const unsigned char[]) {'\x36', '\x7d', '\x9d', '\x3a', '\x80', '\x00', '\x00', '\x00', '\x00', '\x00'} // 'system' in Addr32
#define AEM_ADDR32_PUBLIC (const unsigned char[]) {'\x35', '\xb6', '\xb0', '\x85', '\x80', '\x00', '\x00', '\x00', '\x00', '\x00'} // 'pub11c' in Addr32

#define AEM_FLAG_UINFO 2
#define AEM_FLAG_NEWER 1

#define AEM_MAXLEN_MSGDATA 4194304 // 4 MiB

// Minimum block count: treat zero as this number. Covers overhead, allows larger messages.
// Base: 5 (info + ts) + 64 (sig) + 48 (sealed box) = 117
// ExtMsg: 29/146; 31B .. 1M + 46B
// UplMsg: 46/163; 14B .. 1M + 29B
// IntMsg: 54/171: 6B ..
// OutMsg: 22/139: 38B .. (IntMsg, no E2EE)
// 12 * 16 = 192 (-15 --> 177 min)
#define AEM_MSG_MINBLOCKS 12

#define AEM_API_BOX_SIZE_MAX ((UINT16_MAX + AEM_MSG_MINBLOCKS) * 16)
#define AEM_API_SEALBOX_SIZE (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_SEALBYTES)

#define AEM_PATH_HOME "/var/lib/allears"
#define AEM_PATH_MOUNTDIR AEM_PATH_HOME"/mount"
#define AEM_MOUNTDIR_FLAGS (MS_NOSUID | MS_NOATIME | MS_SILENT)

#define AEM_BACKLOG 25
#define AEM_TLS_TIMEOUT 30

#define AEM_TIMEOUT_MANAGER_RCV 3
#define AEM_TIMEOUT_MANAGER_SND 3

#define AEM_MAXSIZE_EXEC 524288 // 512 KiB

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
	AEM_API_MESSAGE_PUBLIC,
	AEM_API_MESSAGE_UPLOAD,
	AEM_API_PRIVATE_UPDATE,
	AEM_API_SETTING_LIMITS,
	AEM_API_INTERNAL_ADRPK,
	AEM_API_INTERNAL_ERASE,
	AEM_API_INTERNAL_EXIST,
	AEM_API_INTERNAL_LEVEL,
	AEM_API_INTERNAL_MYADR,
	AEM_API_INTERNAL_PUBKS,
	AEM_API_INTERNAL_UINFO
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
