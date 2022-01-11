#ifndef AEM_API_ISREQUESTVALID_H
#define AEM_API_ISREQUESTVALID_H

#include <stdbool.h>

bool isRequestValid(const char * const req, const size_t lenReq, bool * const keepAlive, long * const clen);

#endif
