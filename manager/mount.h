#ifndef AEM_MOUNT_H
#define AEM_MOUNT_H

int createMount(const pid_t pid, const int type, const pid_t pid_account, const pid_t pid_storage);
int deleteMount(const pid_t pid);

#endif
