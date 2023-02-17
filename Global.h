#ifndef AEM_GLOBAL_H
#define AEM_GLOBAL_H

#include "Config.h"

#define UINT24_MAX 16777215UL

#define AEM_FD_BINARY 0
#define AEM_FD_PIPE_RD 1
#define AEM_FD_PIPE_WR 2
#define AEM_FD_ROOT 2

#define AEM_INTCOM_RESPONSE_OK       INT32_MIN
#define AEM_INTCOM_RESPONSE_ERR      (INT32_MIN + 1)
#define AEM_INTCOM_RESPONSE_USAGE    (INT32_MIN + 2)
#define AEM_INTCOM_RESPONSE_PERM     (INT32_MIN + 3)
#define AEM_INTCOM_RESPONSE_EXIST    (INT32_MIN + 4)
#define AEM_INTCOM_RESPONSE_NOTEXIST (INT32_MIN + 5)
#define AEM_INTCOM_RESPONSE_PARTIAL  (INT32_MIN + 6)
#define AEM_INTCOM_RESPONSE_LIMIT    (INT32_MIN + 7)
#define AEM_INTCOM_RESPONSE_CRYPTO   (INT32_MIN + 8)
#define AEM_INTCOM_RESPONSE_FORBID   (INT32_MIN + 9)

enum aem_internal_enquiry {
	AEM_ENQUIRY_MX,
	AEM_ENQUIRY_A,
	AEM_ENQUIRY_IP,
	AEM_ENQUIRY_DKIM
};

#define AEM_ADDRESSES_PER_USER 31 // (2^5)-1
#define AEM_MINLEN_UINFO (4 + AEM_LEN_PRIVATE)
#define AEM_MAXLEN_UINFO (AEM_MINLEN_UINFO + (AEM_ADDRESSES_PER_USER * 9))

#define AEM_ADDR_FLAG_SHIELD 128
// 64 unused
#define AEM_ADDR_FLAG_ORIGIN 32
#define AEM_ADDR_FLAG_SECURE 16
#define AEM_ADDR_FLAG_ATTACH  8
#define AEM_ADDR_FLAG_ALLVER  4
#define AEM_ADDR_FLAG_ACCEXT  2
#define AEM_ADDR_FLAG_ACCINT  1
#define AEM_ADDR_FLAGS_DEFAULT (AEM_ADDR_FLAG_ACCEXT | AEM_ADDR_FLAG_ALLVER | AEM_ADDR_FLAG_ATTACH)

#define AEM_SMTP_MAX_TO 128 // RFC5321: must accept 100 recipients at minimum
#define AEM_SMTP_CHUNKSIZE 65536

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

#define AEM_ADDR32_ADMIN  (const unsigned char[]) {'\xa6', '\xd0', '\x35', '\x0e', '\x75', '\x85', '\x68', '\x18'} // 'administrator' in Addr32
#define AEM_ADDR32_SYSTEM (const unsigned char[]) {'\x36', '\x7d', '\x9d', '\x3a', '\x80', '\x00', '\x00', '\x00', '\x00', '\x00'} // 'system' in Addr32
#define AEM_ADDR32_PUBLIC (const unsigned char[]) {'\x35', '\xb6', '\xb0', '\x85', '\x80', '\x00', '\x00', '\x00', '\x00', '\x00'} // 'pub11c' in Addr32

#define AEM_FLAG_UINFO 2
#define AEM_FLAG_NEWER 1

// Control-Enriched Text (CET)
#define AEM_CET_CHAR_BLD 0x06 // Bold
#define AEM_CET_CHAR_ITA 0x07 // Italics
#define AEM_CET_CHAR_UNL 0x08 // Underline
#define AEM_CET_CHAR_STR 0x09 // Strikethrough
// 0x0A = LF
#define AEM_CET_CHAR_SEP 0x0B // Separator (internal use)
#define AEM_CET_CHAR_LNK 0x0C // a, frame, iframe (+1 = HTTPS)
#define AEM_CET_CHAR_FIL 0x0E // img, audio, video, source, object, embed (+1 = HTTPS)

/*
	Minimum block count: start from this number, not zero. Covers overhead, allows larger messages.
	Base: 5 (info + ts) + 64 (sig) + 48 (sealed box) = 117
	ExtMsg: 29/146; 31B .. 1M + 30B
	UplMsg: 17/134; 43B .. 1M + 42B = 1048618 (Attachment, body + filename)
	UplMsg: 41/158; 19B .. 1M + 18B = 1048594 (Upload, body + filename)
	IntMsg: 54/171: 6B ..
	OutMsg: 22/139: 38B .. (IntMsg, no E2EE)
*/
#define AEM_MSG_MAXSIZE 1048752 // ((2^16 - 1) + 12) * 16 = 1048752; 1M + 176B
#define AEM_MSG_MINBLOCKS 12
#define AEM_MSG_MINSIZE (AEM_MSG_MINBLOCKS * 16) // 12 * 16 = 192 (-15 --> 177 min)
#define AEM_MSG_MINSIZE_DEC (AEM_MSG_MINSIZE - crypto_box_SEALBYTES)

#define AEM_API_BOX_SIZE_MAX 1048635 // (((2^16 - 1) + 12) * 16) - 117
#define AEM_API_SEALBOX_SIZE (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_SEALBYTES)

#define AEM_PATH_HOME "/var/lib/allears"
#define AEM_PATH_MOUNTDIR AEM_PATH_HOME"/mount"

#define AEM_SMTP_MAX_SIZE_BODY      4194304 // 4 MiB. RFC5321: min. 64k
#define AEM_SMTP_MAX_SIZE_BODY_STR "4194304"

#define AEM_TIMEOUT_MANAGER_RCV 3
#define AEM_TIMEOUT_MANAGER_SND 3

#define AEM_MAXSIZE_EXEC 131072 // 128 KiB

#define AEM_INTCOM_SOCKPATH_LEN 23
#define AEM_INTCOM_SOCKPATH_ACCOUNT "\0All-Ears Mail: Account"
#define AEM_INTCOM_SOCKPATH_DELIVER "\0All-Ears Mail: Deliver"
#define AEM_INTCOM_SOCKPATH_ENQUIRY "\0All-Ears Mail: Enquiry"
#define AEM_INTCOM_SOCKPATH_STORAGE "\0All-Ears Mail: Storage"

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
	AEM_API_MESSAGE_SENDER,
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

enum aem_mta_commands {
	AEM_MTA_GETUPK_NORMAL,
	AEM_MTA_GETUPK_SHIELD
};

enum aem_acc_commands {
	AEM_ACC_STORAGE_LEVELS,
	AEM_ACC_STORAGE_LIMITS,
	AEM_ACC_STORAGE_AMOUNT
};

enum aem_process_types {
	AEM_PROCESSTYPE_WEB_CLR,
	AEM_PROCESSTYPE_WEB_ONI,
	AEM_PROCESSTYPE_API_CLR,
	AEM_PROCESSTYPE_API_ONI,
	AEM_PROCESSTYPE_MTA,
	AEM_PROCESSTYPE_ACCOUNT,
	AEM_PROCESSTYPE_DELIVER,
	AEM_PROCESSTYPE_ENQUIRY,
	AEM_PROCESSTYPE_STORAGE,
	AEM_PROCESSTYPES_COUNT
};

// XXX The above and below lists MUST be in the same order

#define AEM_PATH_EXE { \
	AEM_PATH_HOME"/bin/aem-web-clr", \
	AEM_PATH_HOME"/bin/aem-web-oni", \
	AEM_PATH_HOME"/bin/aem-api-clr", \
	AEM_PATH_HOME"/bin/aem-api-oni", \
	AEM_PATH_HOME"/bin/aem-mta", \
	AEM_PATH_HOME"/bin/aem-account", \
	AEM_PATH_HOME"/bin/aem-deliver", \
	AEM_PATH_HOME"/bin/aem-enquiry", \
	AEM_PATH_HOME"/bin/aem-storage" \
}

#define AEM_NICE { \
	/*Web-Clr*/   4, \
	/*Web-Oni*/   8, \
	/*API-Clr*/  -4, \
	/*API-Oni*/  -2, \
	/*MTA*/      -8, \
	/*Account*/ -16, \
	/*Deliver*/  -3, \
	/*Enquiry*/ -10, \
	/*Storage*/ -18 \
}

#endif
