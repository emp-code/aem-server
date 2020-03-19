#ifndef AEM_INCLUDES_TOUTF8_H
#define AEM_INCLUDES_TOUTF8_H

bool isUtf8(const char * const charset, const size_t len);
char *toUtf8(const char * const input, const size_t lenInput, int * const lenOut, const char * const charset, const size_t lenCs);

#endif
