#ifndef AEM_UNIXSOCKETCLIENT_H
#define AEM_UNIXSOCKETCLIENT_H

int accountSocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg);
int storageSocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg);
int enquirySocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg);

void setAccountPid(const pid_t pid);
void setStoragePid(const pid_t pid);
void setEnquiryPid(const pid_t pid);

#endif
