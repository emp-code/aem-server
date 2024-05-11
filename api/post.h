#ifndef AEM_API_POST_H
#define AEM_API_POST_H

void setOurDomain(const unsigned char * const crt, const size_t lenCrt);

#ifdef AEM_API_REQ_LEN
void aem_api_process(unsigned char req[AEM_API_REQ_LEN], const bool isPost);
#endif

#endif
