#ifndef AEM_MESSAGE_H
#define AEM_MESSAGE_H

#include <stdint.h>

void aem_msg_init(unsigned char * const msg, const int type, uint64_t ts);

#endif
