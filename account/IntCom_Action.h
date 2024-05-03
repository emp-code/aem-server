#ifndef AEM_INTCOM_ACTION_H
#define AEM_INTCOM_ACTION_H

int32_t conn_api(const uint32_t operation, unsigned char *msg, size_t lenMsg, unsigned char **res);
int32_t conn_mta(const uint32_t operation, const unsigned char * const msg, const size_t lenMsg, unsigned char **res);
int32_t conn_sto(const uint32_t operation, unsigned char **res);

#endif
