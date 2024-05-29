#ifndef AEM_INTCOM_ACTION_H
#define AEM_INTCOM_ACTION_H

#include <stdint.h>

int32_t conn_acc(const uint32_t operation, const unsigned char * const msg, const size_t lenMsg, unsigned char **res);
int32_t conn_api(const uint32_t operation, unsigned char * const msg, const size_t lenMsg, unsigned char **res);
int32_t conn_dlv(const uint32_t operation, unsigned char * const msg, const size_t lenMsg, unsigned char **res);

#endif
