#ifndef AEM_INTCOM_CLIENT_H
#define AEM_INTCOM_CLIENT_H

#include "IntCom_Common.h"

int32_t intcom(const aem_intcom_type_t intcom_type, const int operation, const unsigned char * const msg, const size_t lenMsg, unsigned char ** const out, const int32_t expectedLenOut);

#if defined(AEM_API) || defined(AEM_MTA)
void setAccountPid(const pid_t pid);
void setEnquiryPid(const pid_t pid);
#endif
void setStoragePid(const pid_t pid);

#endif
