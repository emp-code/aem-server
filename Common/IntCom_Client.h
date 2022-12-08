#ifndef AEM_INTCOM_CLIENT_H
#define AEM_INTCOM_CLIENT_H

#include <stdint.h>

typedef enum {
	AEM_INTCOM_TYPE_ACCOUNT,
	AEM_INTCOM_TYPE_DELIVER,
	AEM_INTCOM_TYPE_ENQUIRY,
	AEM_INTCOM_TYPE_STORAGE,
	AEM_INTCOM_TYPE_NULL
} aem_intcom_type_t;

int32_t intcom(const aem_intcom_type_t intcom_type, const int operation, const unsigned char * const msg, const size_t lenMsg, unsigned char ** const out, const int32_t expectedLenOut);

#if defined(AEM_API) || defined(AEM_MTA)
void setAccountPid(const pid_t pid);
#endif
#if defined(AEM_API) || defined(AEM_DELIVER)
void setEnquiryPid(const pid_t pid);
#endif
void setStoragePid(const pid_t pid);
#if defined(AEM_MTA)
void setDeliverPid(const pid_t pid);
#endif

#ifdef AEM_MTA
int intcom_stream_open(const unsigned char * const ss_header);
int intcom_stream_send(const int sock, crypto_secretstream_xchacha20poly1305_state * const ss_state, const unsigned char * const src, const size_t lenSrc);
int32_t intcom_stream_end(const int sock, crypto_secretstream_xchacha20poly1305_state * const ss_state);
#endif

#endif
