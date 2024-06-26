#ifndef AEM_API_ERROR_H
#define AEM_API_ERROR_H

#define AEM_API_STATUS_OK 0x00
// 0x01-0x0F	Client

// 0xA0-0xAF	Basic
#define AEM_API_ERR_INTERNAL 0xA0
#define AEM_API_ERR_CMD      0xA1
#define AEM_API_ERR_PARAM    0xA2
#define AEM_API_ERR_POST     0xA3
#define AEM_API_ERR_RECV     0xA4
#define AEM_API_ERR_DECRYPT  0xA5
#define AEM_API_ERR_LEVEL    0xA6

// 0xB0-0xBF General
#define AEM_API_ERR_MESSAGE_BROWSE_NOMORE    0xB0
#define AEM_API_ERR_MESSAGE_BROWSE_NOTFOUND  0xB1
#define AEM_API_ERR_MESSAGE_DELETE_NOTFOUND  0xB2

// 0xC0-0xC9	Account
#define AEM_API_ERR_ACCOUNT_EXIST            0xC0
#define AEM_API_ERR_ACCOUNT_NOTEXIST         0xC1
#define AEM_API_ERR_ACCOUNT_FORBIDMASTER     0xC2
#define AEM_API_ERR_ACCOUNT_DELETE_NOSTORAGE 0xC3

// 0xDA-0xDF	Address/Create|Delete|Update
#define AEM_API_ERR_ADDRESS_CREATE_INUSE     0xDA
#define AEM_API_ERR_ADDRESS_CREATE_ATLIMIT   0xDB
#define AEM_API_ERR_ADDRESS_DELETE_SOMEFOUND 0xDC
#define AEM_API_ERR_ADDRESS_DELETE_NONEFOUND 0xDD
#define AEM_API_ERR_ADDRESS_UPDATE_SOMEFOUND 0xDE
#define AEM_API_ERR_ADDRESS_UPDATE_NONEFOUND 0xDF

// 0xE0-0xE9	Message/Create
#define AEM_API_ERR_MESSAGE_CREATE_EXT_MINLEVEL 0xE0
#define AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_ADFR 0xE1
#define AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_ADTO 0xE2
#define AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_RPLY 0xE3
#define AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_SUBJ 0xE4
#define AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_UTF8 0xE5
#define AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_CTRL 0xE6
#define AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_SIZE 0xE7
#define AEM_API_ERR_MESSAGE_CREATE_EXT_BDY_LONG 0xE8
#define AEM_API_ERR_MESSAGE_CREATE_EXT_MYDOMAIN 0xE9

#define AEM_API_ERR_MESSAGE_CREATE_INT_OWN_ADDR 0xEE
#define AEM_API_ERR_MESSAGE_CREATE_INT_REC_DENY 0xEF

// 0xF0-0xF9	Message/Create sendMail()
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_GREET 0xF0
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_EHLO  0xF1
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_STLS  0xF2
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_SHAKE 0xF3
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_NOTLS 0xF4
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_MAIL  0xF5
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_RCPT  0xF6
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_DATA  0xF7
#define AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_BODY  0xF8
// 0xF9 unused

// 0xFA-0xFF	Message/Create Int
#define AEM_API_ERR_MESSAGE_CREATE_INT_TOOSHORT     0xFA
#define AEM_API_ERR_MESSAGE_CREATE_INT_TS_INVALID   0xFB
#define AEM_API_ERR_MESSAGE_CREATE_INT_SUBJECT_SIZE 0xFC
#define AEM_API_ERR_MESSAGE_CREATE_INT_ADDR_NOTOWN  0xFD
#define AEM_API_ERR_MESSAGE_CREATE_INT_TO_NOTACCEPT 0xFE
#define AEM_API_ERR_MESSAGE_CREATE_INT_TO_SELF      0xFF

#endif
