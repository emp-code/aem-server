#ifndef AEM_DELIVER_H
#define AEM_DELIVER_H

int32_t deliverEmail(const struct emailMeta * const meta, struct emailInfo * const email, unsigned char * const src, size_t lenSrc);

#endif
