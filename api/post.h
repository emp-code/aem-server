#ifndef AEM_API_POST_H
#define AEM_API_POST_H

void setOurDomain(const unsigned char * const crt, const size_t lenCrt);

#ifdef AEM_API_REQ_LEN
void aem_api_process(const unsigned char * const req, const bool isPost);
#endif

#endif
