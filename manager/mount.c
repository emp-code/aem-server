#include <grp.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "mount.h"

#include "../Global.h"

#define AEM_MODE_RO (S_IRUSR | S_IRGRP)
#define AEM_MODE_XO (S_IXUSR | S_IXGRP)
#define AEM_MODE_RW (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
#define AEM_MODE_RX (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP)

#define AEM_MOUNT_ISFILE 1
#define AEM_MOUNT_RDONLY 2

static gid_t getAemGroup(void) {
	const struct passwd * const p = getpwnam("allears");
	return (p == NULL) ? 0 : p->pw_gid;
}

static int bindMount(const char * const source, const char * const target, const int flags) {
	if (flags & AEM_MOUNT_ISFILE) {
		if (mknod(target, S_IFREG, 0) != 0) return -1;
	} else {
		if (mkdir(target, 1000) != 0) return -1;
	}

	unsigned long mountFlags = MS_BIND | MS_REMOUNT | MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_SILENT;
	if (flags & AEM_MOUNT_RDONLY) mountFlags |= MS_RDONLY;

	return (
	   mount(source, target, NULL, MS_BIND,       NULL) == 0
	&& mount(NULL,   target, NULL, MS_UNBINDABLE, NULL) == 0
	&& mount(NULL,   target, NULL, mountFlags,    NULL) == 0
	) ? 0 : -1;
}

static int makeSpecial(const char * const name, const mode_t mode, const unsigned int major, const unsigned int minor, const gid_t aemGroup) {
	char path[64];
	strcpy(path, AEM_PATH_MOUNTDIR"/dev/");
	strcpy(path + strlen(path), name);
	return (
	   mknod(path, S_IFCHR | mode, makedev(major, minor)) == 0
	&& chown(path, 0, aemGroup) == 0
	) ? 0 : -1;
}

int createMount(const int type) {
	const gid_t aemGroup = getAemGroup();
	if (aemGroup == 0) return -1;
	umask(0);

	int fsmode, nr_inodes;
	switch (type) {
		case AEM_PROCESSTYPE_MTA:
		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI: fsmode = 1110; nr_inodes = 9; break;

		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI:
		case AEM_PROCESSTYPE_ENQUIRY: fsmode = 1110; nr_inodes = 12; break;

		case AEM_PROCESSTYPE_ACCOUNT:
		case AEM_PROCESSTYPE_STORAGE: fsmode = 1770; nr_inodes = 11; break;

		default: return -1;
	}

	char tmpfs_opts[64];
	sprintf(tmpfs_opts, "size=1,uid=0,gid=%d,mode=%d,nr_inodes=%d", aemGroup, fsmode, nr_inodes);

	if (
	   mount("tmpfs", AEM_PATH_MOUNTDIR, "tmpfs", AEM_MOUNTDIR_FLAGS, tmpfs_opts) != 0
	|| mount(NULL,    AEM_PATH_MOUNTDIR, NULL,    MS_UNBINDABLE,      NULL)       != 0
	) return -1;

	if (
	   mkdir(AEM_PATH_MOUNTDIR"/dev", AEM_MODE_XO | S_ISVTX) != 0
	|| chown(AEM_PATH_MOUNTDIR"/dev", 0, aemGroup) != 0
	|| makeSpecial("null",    AEM_MODE_RW, 1, 3, aemGroup) != 0
	|| makeSpecial("zero",    AEM_MODE_RO, 1, 5, aemGroup) != 0
	|| makeSpecial("full",    AEM_MODE_RW, 1, 7, aemGroup) != 0
	|| makeSpecial("random",  AEM_MODE_RO, 1, 8, aemGroup) != 0
	|| makeSpecial("urandom", AEM_MODE_RO, 1, 9, aemGroup) != 0
	|| bindMount("/dev/log", AEM_PATH_MOUNTDIR"/dev/log", AEM_MOUNT_ISFILE) != 0
	) return -1;

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT:
			if (
			   bindMount(AEM_PATH_HOME"/Account.aem", AEM_PATH_MOUNTDIR"/Account.aem", AEM_MOUNT_ISFILE) != 0
			|| bindMount(AEM_PATH_HOME"/Settings.aem", AEM_PATH_MOUNTDIR"/Settings.aem", AEM_MOUNT_ISFILE) != 0
			) {syslog(LOG_ERR, "%m"); return -1;}
		break;

		case AEM_PROCESSTYPE_ENQUIRY:
			if (
			   bindMount("/usr/share/ca-certificates/mozilla/", AEM_PATH_MOUNTDIR"/ssl-certs",             AEM_MOUNT_RDONLY) != 0
			|| bindMount(AEM_PATH_HOME"/GeoLite2-Country.mmdb", AEM_PATH_MOUNTDIR"/GeoLite2-Country.mmdb", AEM_MOUNT_RDONLY | AEM_MOUNT_ISFILE) != 0
			|| bindMount(AEM_PATH_HOME"/GeoLite2-ASN.mmdb",     AEM_PATH_MOUNTDIR"/GeoLite2-ASN.mmdb",     AEM_MOUNT_RDONLY | AEM_MOUNT_ISFILE) != 0
			) return -1;
		break;

		case AEM_PROCESSTYPE_STORAGE:
			if (
			   bindMount(AEM_PATH_HOME"/Stindex.aem", AEM_PATH_MOUNTDIR"/Stindex.aem", AEM_MOUNT_ISFILE) != 0
			|| bindMount(AEM_PATH_HOME"/MessageData", AEM_PATH_MOUNTDIR"/MessageData", 0) != 0
			) return -1;
		break;

		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI:
			if (
			   mkdir(AEM_PATH_MOUNTDIR"/etc", AEM_MODE_XO | S_ISVTX) != 0
			|| chown(AEM_PATH_MOUNTDIR"/etc", 0, aemGroup) != 0
			|| bindMount("/etc/localtime",                      AEM_PATH_MOUNTDIR"/etc/localtime", AEM_MOUNT_RDONLY | AEM_MOUNT_ISFILE) != 0
			|| bindMount("/usr/share/ca-certificates/mozilla/", AEM_PATH_MOUNTDIR"/ssl-certs",     AEM_MOUNT_RDONLY) != 0
			) return -1;
		break;
	}

	if (mkdir(AEM_PATH_MOUNTDIR"/old_root", 1000) != 0) return -1;

	if (type != AEM_PROCESSTYPE_ACCOUNT && type != AEM_PROCESSTYPE_STORAGE) {
		umask(0777);
		if (mount(NULL, AEM_PATH_MOUNTDIR, NULL, AEM_MOUNTDIR_FLAGS | MS_REMOUNT | MS_RDONLY, tmpfs_opts) != 0) return -1;
	} else {
		umask(0077);
	}

	if (syscall(SYS_pivot_root, AEM_PATH_MOUNTDIR, AEM_PATH_MOUNTDIR"/old_root") != 0) return -1;

	const int fdRoot = open("/", O_PATH | O_DIRECTORY | O_NOFOLLOW);
	if (fdRoot != 0) {syslog(LOG_ERR, "fdRoot failed: fd=%d; %m", fdRoot); return -1;}

	return (chroot("/old_root") == 0 && chdir("/") == 0) ? 0 : -1;
}
