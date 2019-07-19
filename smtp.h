#ifndef AEM_SMTP_H
#define AEM_SMTP_H

void respond_smtp(const int sock, const size_t lenDomain, const char *domain, const unsigned long ip);

#endif
