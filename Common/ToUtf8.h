#ifndef AEM_INCLUDES_TOUTF8_H
#define AEM_INCLUDES_TOUTF8_H

bool isUtf8(const char * const charset);
char *toUtf8(const char * const input, const size_t lenInput, size_t * const lenOut, const char * const charset);

#endif
