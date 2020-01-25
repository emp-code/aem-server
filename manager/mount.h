#ifndef AEM_MOUNT_H
#define AEM_MOUNT_H

int createMount(const pid_t pid, const int type);
int deleteMount(const pid_t pid, const int type);

#endif
