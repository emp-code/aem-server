#ifndef AEM_CLIENTACTION_H
#define AEM_CLIENTACTION_H

#ifdef AEM_STORAGE
void conn_acc(const int sock, const unsigned char * const dec, const size_t lenDec);
#endif
void conn_api(const int sock, const unsigned char * const dec, const size_t lenDec);
void conn_mta(const int sock, const unsigned char * const dec, const size_t lenDec);

#endif
