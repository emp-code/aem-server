#ifndef AEM_API_RESPOND_H
#define AEM_API_RESPOND_H

void setRbk(const unsigned char * const newKey);
void clrRbk(void);

void unauthResponse(const unsigned char code);
void apiResponse(const unsigned char * const data, const size_t lenData);

#endif
