#include <ctype.h> // for isxdigit
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> // for memlockall
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>

#include "global.h"

#define AEM_MODE_RO S_IRUSR | S_IRGRP
#define AEM_MODE_RW S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
#define AEM_MODE_RX S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP

static gid_t allearsGroup;

static void setGroup(void) {
	const struct passwd * const p = getpwnam("allears");
	allearsGroup = p->pw_gid;
}

static int rxbind(const char * const source, const char * const target) {
	return (
	   mount(source, target, NULL, MS_BIND, "") == 0
	&& mount(NULL,   target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOATIME, NULL) == 0
	) ? 0 : -1;
}

static int rwbind(const char * const source, const char * const target) {
	return (
	   mount(source, target, NULL, MS_BIND, "") == 0
	&& mount(NULL,   target, NULL, MS_BIND | MS_REMOUNT | MS_NOEXEC | MS_NOSUID | MS_NODEV | MS_NOATIME, NULL) == 0
	) ? 0 : -1;
}

static int dirMount(const pid_t pid, const char * const sub, const char * const src) {
	char path[100];
	snprintf(path, 100, AEM_CHROOT"/%d/%s", pid, sub);

	return (mkdir(path, 0) == 0 && rxbind(src, path) == 0) ? 0 : -1;
}

static int dirMake(const pid_t pid, const char * const sub) {
	char path[100];
	snprintf(path, 100, AEM_CHROOT"/%d/%s", pid, sub);

	return (
	   mkdir(path, AEM_MODE_RX) == 0
	&& lchown(path, 0, allearsGroup) == 0
	) ? 0 : -1;
}

static int makeSpecial(const pid_t pid, const char * const name, const unsigned int major, const unsigned int minor) {
	char path[100];
	snprintf(path, 100, AEM_CHROOT"/%d/dev/%s", pid, name);
	return (
	   mknod(path, S_IFCHR | AEM_MODE_RW, makedev(major, minor)) == 0
	&& lchown(path, 0, allearsGroup) == 0
	) ? 0 : -1;
}

int createMount(const pid_t pid, const int type, const pid_t pid_account, const pid_t pid_storage) {
	umask(0);
	setGroup();

	char tmpfs_opts[50];
	if (type == AEM_PROCESSTYPE_ACCOUNT || type == AEM_PROCESSTYPE_STORAGE)
		sprintf(tmpfs_opts, "uid=0,gid=%d,mode=0770,size=1,nr_inodes=50", allearsGroup);
	else
		sprintf(tmpfs_opts, "uid=0,gid=%d,mode=0550,size=1,nr_inodes=50", allearsGroup);

	char path[50];
	snprintf(path, 50, AEM_CHROOT"/%d", pid);
	if (mkdir(path, 0) != 0 || mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NOATIME, tmpfs_opts) != 0) return -1;

	if (
	   dirMake(pid, "dev") != 0
	|| dirMake(pid, "usr") != 0
	|| dirMake(pid, "usr/bin") != 0
	) return -1;

	if (
	   dirMount(pid, "lib", "/lib") != 0
	|| dirMount(pid, "lib64", "/lib64") != 0
	|| dirMount(pid, "usr/lib", "/usr/lib") != 0
	|| dirMount(pid, "usr/lib64", "/usr/lib64") != 0
	) return -1;

	const char *bin;

	switch (type) {
		case AEM_PROCESSTYPE_MTA: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-mta", pid); bin = "/usr/bin/allears/allears-mta"; break;
		case AEM_PROCESSTYPE_API: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-api", pid); bin = "/usr/bin/allears/allears-api"; break;
		case AEM_PROCESSTYPE_WEB: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-web", pid); bin = "/usr/bin/allears/allears-web"; break;
		case AEM_PROCESSTYPE_ACCOUNT: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-account", pid); bin = "/usr/bin/allears/allears-account"; break;
		case AEM_PROCESSTYPE_STORAGE: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-storage", pid); bin = "/usr/bin/allears/allears-storage"; break;
		default: return -1;
	}

	if (mknod(path, S_IFREG, 0) != 0) return -1;
	if (rxbind(bin, path) != 0) return -1;

	snprintf(path, 50, AEM_CHROOT"/%d/dev/log", pid);
	if (mknod(path, S_IFREG, 0) != 0) return -1;
	if (rwbind("/dev/log", path) != 0) return -1;

	if (
	   makeSpecial(pid, "null",    1, 3) != 0
	|| makeSpecial(pid, "zero",    1, 5) != 0
	|| makeSpecial(pid, "full",    1, 7) != 0
	|| makeSpecial(pid, "random",  1, 8) != 0
	|| makeSpecial(pid, "urandom", 1, 9) != 0
	) return -1;

	if (type == AEM_PROCESSTYPE_ACCOUNT) {
		sprintf(path, AEM_CHROOT"/%d/User.aem", pid);
		if (mknod(path, S_IFREG, 0) != 0) return -1;
		if (rwbind("/var/lib/allears/User.aem", path) != 0) return -1;

		sprintf(path, AEM_CHROOT"/%d/Addr.aem", pid);
		if (mknod(path, S_IFREG, 0) != 0) return -1;
		if (rwbind("/var/lib/allears/Addr.aem", path) != 0) return -1;
	} else if (type == AEM_PROCESSTYPE_STORAGE) {
		sprintf(path, AEM_CHROOT"/%d/Message.aem", pid);
		if (mknod(path, S_IFREG, 0) != 0) return -1;
		if (rwbind("/var/lib/allears/Message.aem", path) != 0) return -1;

		sprintf(path, AEM_CHROOT"/%d/Stindex.aem", pid);
		if (mknod(path, S_IFREG, 0) != 0) return -1;
		if (rwbind("/var/lib/allears/Stindex.aem", path) != 0) return -1;
	}

	if (type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_MTA) {
		char pth2[50];

		sprintf(path, AEM_CHROOT"/%d/Account.sck", pid);
		sprintf(pth2, AEM_CHROOT"/%d/Account.sck", pid_account);
		if (mknod(path, S_IFREG, 0) != 0) return -1;
		if (rwbind(pth2, path) != 0) return -1;

		sprintf(path, AEM_CHROOT"/%d/Storage.sck", pid);
		sprintf(pth2, AEM_CHROOT"/%d/Storage.sck", pid_storage);
		if (mknod(path, S_IFREG, 0) != 0) return -1;
		if (rwbind(pth2, path) != 0) return -1;
	}

	if (type == AEM_PROCESSTYPE_ACCOUNT || type == AEM_PROCESSTYPE_STORAGE) return 0;

	sprintf(path, AEM_CHROOT"/%d", pid);
	sprintf(tmpfs_opts, "uid=0,gid=%d,mode=0550,size=1,nr_inodes=50", allearsGroup);
	return mount(NULL, path, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOATIME, tmpfs_opts);
}

int deleteMount(const pid_t pid, const int type) {
	char path[50];

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-account", pid); break;
		case AEM_PROCESSTYPE_STORAGE: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-storage", pid); break;

		case AEM_PROCESSTYPE_WEB: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-web", pid); break;
		case AEM_PROCESSTYPE_API: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-api", pid); break;
		case AEM_PROCESSTYPE_MTA: snprintf(path, 50, AEM_CHROOT"/%d/usr/bin/allears-mta", pid); break;

		default: return -1;
	}
	umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);

	snprintf(path, 50, AEM_CHROOT"/%d/Account.sck", pid); umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/Storage.sck", pid); umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/Message.aem", pid); umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/Addr.aem", pid);    umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/User.aem", pid);    umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/dev/log", pid);     umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/lib64", pid);       umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/lib", pid);         umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/usr/lib64/", pid);  umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	snprintf(path, 50, AEM_CHROOT"/%d/usr/lib/", pid);    umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);

	snprintf(path, 50, AEM_CHROOT"/%d", pid);
	umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	rmdir(path);

	return pid;
}
