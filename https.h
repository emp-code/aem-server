#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

void respond_https(int sock, const unsigned char *httpsCert, const size_t lenHttpsCert, const unsigned char *httpsKey, const size_t lenHttpsKey, const uint32_t clientIp, const unsigned char seed[16]);

#endif
