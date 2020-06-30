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

#include "mount.h"

#include "../Global.h"

#define AEM_MODE_RO (S_IRUSR | S_IRGRP)
#define AEM_MODE_XO (S_IXUSR | S_IXGRP)
#define AEM_MODE_RW (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
#define AEM_MODE_RX (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP)

static gid_t aemGroup;

static int setAemGroup(void) {
	const struct passwd * const p = getpwnam("allears");
	if (p == NULL) return -1;
	aemGroup = p->pw_gid;
	return 0;
}

static int bindMount(const char * const source, const char * const target, const mode_t mode, const bool allowExec, const bool isDir) {
	if (isDir) {
		if (mkdir(target, 0) != 0) return -1;
	} else {
		if (mknod(target, S_IFREG, 0) != 0) return -1;
	}

	if (
	   chown(target, 0, 0) != 0
	|| chmod(target, 0) != 0
	|| mount(source, target, NULL, MS_BIND, "") != 0
	|| mount("",     target, "",   MS_UNBINDABLE, "") != 0
	) return -1;

	unsigned long mountFlags = MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOATIME | MS_SILENT;

	if (!allowExec)
		mountFlags |= MS_NOEXEC;

	if ((mode & S_IWUSR) == 0)
		mountFlags |= MS_RDONLY;

	return mount(NULL, target, NULL, mountFlags, NULL);
}

static int dirMount(const pid_t pid, const char * const sub, const char * const src, const mode_t mode, const bool allowExec) {
	char path[512];
	sprintf(path, AEM_MOUNTDIR"/%d/%s", pid, sub);
	return bindMount(src, path, mode, allowExec, true);
}

static int dirMake(const pid_t pid, const char * const sub) {
	char path[512];
	sprintf(path, AEM_MOUNTDIR"/%d/%s", pid, sub);

	return (
	   mkdir(path, AEM_MODE_XO) == 0
	&& chown(path, 0, aemGroup) == 0
	) ? 0 : -1;
}

static int makeSpecial(const pid_t pid, const char * const name, const mode_t mode, const unsigned int major, const unsigned int minor) {
	char path[512];
	sprintf(path, AEM_MOUNTDIR"/%d/dev/%s", pid, name);
	return (
	   mknod(path, S_IFCHR | AEM_MODE_RW, makedev(major, minor)) == 0
	&& chown(path, 0, aemGroup) == 0
	&& chmod(path, mode) == 0
	) ? 0 : -1;
}

int createMount(const pid_t pid, const int type) {
	if (setAemGroup() != 0) return -1;
	umask(0);

	char path[512];
	char tmpfs_opts[512];

	int nr_inodes = 0;
	int fsmode = 1000;
	switch (type) {
		case AEM_PROCESSTYPE_MTA: fsmode = 1550; nr_inodes = 16; break;
		case AEM_PROCESSTYPE_API: fsmode = 1550; nr_inodes = 16; break;
		case AEM_PROCESSTYPE_WEB: fsmode = 1550; nr_inodes = 15; break;
		case AEM_PROCESSTYPE_ACCOUNT: fsmode = 1770; nr_inodes = 16; break;
		case AEM_PROCESSTYPE_STORAGE: fsmode = 1770; nr_inodes = 17; break;
		case AEM_PROCESSTYPE_ENQUIRY: fsmode = 1550; nr_inodes = 16; break;
		default: return -1;
	}
	sprintf(tmpfs_opts, "uid=0,gid=%d,mode=%d,size=1,nr_inodes=%d", aemGroup, fsmode, nr_inodes);

	sprintf(path, AEM_MOUNTDIR"/%d", pid);
	if (
	   mkdir(path, 0) != 0
	|| mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NOATIME | MS_SILENT, tmpfs_opts) != 0
	|| mount("", path, "", MS_UNBINDABLE, "") != 0
	) return -1;

	if (
	   dirMake(pid, "dev") != 0
	|| dirMake(pid, "usr") != 0
	|| dirMake(pid, "usr/bin") != 0
	) return -1;

	if (
	   dirMount(pid, "lib",       "/lib",       AEM_MODE_XO, true) != 0
	|| dirMount(pid, "lib64",     "/lib64",     AEM_MODE_XO, true) != 0
	|| dirMount(pid, "usr/lib",   "/usr/lib",   AEM_MODE_XO, true) != 0
	|| dirMount(pid, "usr/lib64", "/usr/lib64", AEM_MODE_XO, true) != 0
	) return -1;

	if ((type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_ENQUIRY) && (
	   dirMount(pid, "ssl-certs", "/usr/share/ca-certificates/mozilla/", AEM_MODE_RX, false) != 0
	)) return -1;

	const char *bin;

	switch (type) {
		case AEM_PROCESSTYPE_MTA: sprintf(path, AEM_MOUNTDIR"/%d/usr/bin/aem-mta", pid); bin = "/usr/bin/allears/aem-mta"; break;
		case AEM_PROCESSTYPE_API: sprintf(path, AEM_MOUNTDIR"/%d/usr/bin/aem-api", pid); bin = "/usr/bin/allears/aem-api"; break;
		case AEM_PROCESSTYPE_WEB: sprintf(path, AEM_MOUNTDIR"/%d/usr/bin/aem-web", pid); bin = "/usr/bin/allears/aem-web"; break;
		case AEM_PROCESSTYPE_ACCOUNT: sprintf(path, AEM_MOUNTDIR"/%d/usr/bin/aem-account", pid); bin = "/usr/bin/allears/aem-account"; break;
		case AEM_PROCESSTYPE_STORAGE: sprintf(path, AEM_MOUNTDIR"/%d/usr/bin/aem-storage", pid); bin = "/usr/bin/allears/aem-storage"; break;
		case AEM_PROCESSTYPE_ENQUIRY: sprintf(path, AEM_MOUNTDIR"/%d/usr/bin/aem-enquiry", pid); bin = "/usr/bin/allears/aem-enquiry"; break;
		default: return -1;
	}

	if (bindMount(bin, path, AEM_MODE_RO, true, false) != 0) return -1;

	sprintf(path, AEM_MOUNTDIR"/%d/dev/log", pid);
	if (bindMount("/dev/log", path, AEM_MODE_RW, false, false) != 0) return -1;

	if (type == AEM_PROCESSTYPE_MTA) {
		sprintf(path, AEM_MOUNTDIR"/%d/GeoLite2-Country.mmdb", pid);
		if (bindMount("/var/lib/allears/GeoLite2-Country.mmdb", path, AEM_MODE_RO, false, false) != 0) return -1;
	}

	if (
	   makeSpecial(pid, "null",    AEM_MODE_RW, 1, 3) != 0
	|| makeSpecial(pid, "zero",    AEM_MODE_RO, 1, 5) != 0
	|| makeSpecial(pid, "full",    AEM_MODE_RW, 1, 7) != 0
	|| makeSpecial(pid, "random",  AEM_MODE_RO, 1, 8) != 0
	|| makeSpecial(pid, "urandom", AEM_MODE_RO, 1, 9) != 0
	) return -1;

	if (type == AEM_PROCESSTYPE_ACCOUNT) {
		sprintf(path, AEM_MOUNTDIR"/%d/Account.aem", pid);
		if (bindMount("/var/lib/allears/Account.aem", path, AEM_MODE_RW, false, false) != 0) return -1;
	} else if (type == AEM_PROCESSTYPE_STORAGE) {
		sprintf(path, AEM_MOUNTDIR"/%d/Storage.aem", pid);
		if (bindMount("/var/lib/allears/Storage.aem", path, AEM_MODE_RW, false, false) != 0) return -1;

		sprintf(path, AEM_MOUNTDIR"/%d/Stindex.aem", pid);
		if (bindMount("/var/lib/allears/Stindex.aem", path, AEM_MODE_RW, false, false) != 0) return -1;
	}

	if (type == AEM_PROCESSTYPE_ACCOUNT || type == AEM_PROCESSTYPE_STORAGE) return 0;

	sprintf(path, AEM_MOUNTDIR"/%d", pid);
	sprintf(tmpfs_opts, "uid=0,gid=%d,mode=%d,size=1,nr_inodes=%d", aemGroup, fsmode, nr_inodes);
	return mount(NULL, path, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOATIME | MS_SILENT, tmpfs_opts);
}

int deleteMount(const pid_t pid) {
	char path[512];
	sprintf(path, AEM_MOUNTDIR"/%d", pid);
	umount2(path, UMOUNT_NOFOLLOW | MNT_DETACH);
	rmdir(path);

	return pid;
}
