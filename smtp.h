#ifndef AEM_SMTP_H
#define AEM_SMTP_H

void respond_smtp(int sock, mbedtls_x509_crt *srvcert, mbedtls_pk_context *pkey, const unsigned char * const addrKey, const unsigned char seed[16], const char *domain, const size_t lenDomain, const uint32_t clientIp);

#endif
