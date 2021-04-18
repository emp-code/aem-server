#ifndef AEM_CLIENTACTION_H
#define AEM_CLIENTACTION_H

void conn_api(const int sock, const unsigned char * const dec, const size_t lenDec);
void conn_mta(const int sock, const unsigned char * const dec, const size_t lenDec);

#endif
