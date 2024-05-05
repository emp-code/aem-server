#ifndef AEM_API_RESPOND_H
#define AEM_API_RESPOND_H

void setRbk(const unsigned char * const newKey);
void clrRbk(void);

void respond400(void);
void respond403(void);
void respond404(void);
void respond500(void);

void apiResponse(const unsigned char * const data, const size_t lenData);

#endif
