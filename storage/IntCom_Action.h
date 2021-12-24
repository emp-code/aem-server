#ifndef AEM_INTCOM_ACTION_H
#define AEM_INTCOM_ACTION_H

int32_t conn_acc(const uint8_t type, const unsigned char * const msg, const size_t lenMsg, unsigned char **res);
int32_t conn_api(const uint8_t type, unsigned char * const msg, const size_t lenMsg, unsigned char **res);
int32_t conn_mta(const uint8_t type, unsigned char * const msg, const size_t lenMsg, unsigned char **res);

#endif
