#include <grp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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

static int makeSpecial(const char * const name, const mode_t mode, const unsigned int major, const unsigned int minor) {
	char path[512];
	sprintf(path, AEM_MOUNTDIR"/dev/%s", name);
	return (
	   mknod(path, S_IFCHR | mode, makedev(major, minor)) == 0
	&& chown(path, 0, aemGroup) == 0
	) ? 0 : -1;
}

int createMount(const int type) {
	if (setAemGroup() != 0) return -1;
	umask(0);

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

	sprintf(tmpfs_opts, "size=1,uid=0,gid=%d,mode=%d,nr_inodes=%d", aemGroup, fsmode, nr_inodes);
	if (mount("tmpfs", AEM_MOUNTDIR, "tmpfs", AEM_MOUNTDIR_FLAGS, tmpfs_opts) != 0) return -1;
	if (mount("", AEM_MOUNTDIR, "", MS_UNBINDABLE, "") != 0) return -1;

	if (
	   mkdir(AEM_MOUNTDIR"/dev",     AEM_MODE_XO) != 0
	|| mkdir(AEM_MOUNTDIR"/usr",     AEM_MODE_XO) != 0
	|| mkdir(AEM_MOUNTDIR"/usr/bin", AEM_MODE_XO) != 0
	|| chown(AEM_MOUNTDIR"/dev",     0, aemGroup) != 0
	|| chown(AEM_MOUNTDIR"/usr",     0, aemGroup) != 0
	|| chown(AEM_MOUNTDIR"/usr/bin", 0, aemGroup) != 0
	) return -1;

	if (
	   bindMount("/lib",       AEM_MOUNTDIR"/lib",       AEM_MODE_XO, true, true) != 0
	|| bindMount("/lib64",     AEM_MOUNTDIR"/lib64",     AEM_MODE_XO, true, true) != 0
	|| bindMount("/usr/lib",   AEM_MOUNTDIR"/usr/lib",   AEM_MODE_XO, true, true) != 0
	|| bindMount("/usr/lib64", AEM_MOUNTDIR"/usr/lib64", AEM_MODE_XO, true, true) != 0
	) return -1;

	if ((type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_ENQUIRY) && (
	   bindMount("/usr/share/ca-certificates/mozilla/", AEM_MOUNTDIR"/ssl-certs", AEM_MODE_RX, false, true) != 0
	)) return -1;

	const char *path;
	const char *bin;
	switch (type) {
		case AEM_PROCESSTYPE_MTA: path = AEM_MOUNTDIR"/usr/bin/aem-mta"; bin = "/usr/bin/allears/aem-mta"; break;
		case AEM_PROCESSTYPE_API: path = AEM_MOUNTDIR"/usr/bin/aem-api"; bin = "/usr/bin/allears/aem-api"; break;
		case AEM_PROCESSTYPE_WEB: path = AEM_MOUNTDIR"/usr/bin/aem-web"; bin = "/usr/bin/allears/aem-web"; break;
		case AEM_PROCESSTYPE_ACCOUNT: path = AEM_MOUNTDIR"/usr/bin/aem-account"; bin = "/usr/bin/allears/aem-account"; break;
		case AEM_PROCESSTYPE_STORAGE: path = AEM_MOUNTDIR"/usr/bin/aem-storage"; bin = "/usr/bin/allears/aem-storage"; break;
		case AEM_PROCESSTYPE_ENQUIRY: path = AEM_MOUNTDIR"/usr/bin/aem-enquiry"; bin = "/usr/bin/allears/aem-enquiry"; break;
		default: return -1;
	}
	if (bindMount(bin, path, AEM_MODE_RO, true, false) != 0) return -1;

	if (bindMount("/dev/log", AEM_MOUNTDIR"/dev/log", AEM_MODE_RW, false, false) != 0) return -1;

	if (type == AEM_PROCESSTYPE_MTA) {
		if (bindMount("/var/lib/allears/GeoLite2-Country.mmdb", AEM_MOUNTDIR"/GeoLite2-Country.mmdb", AEM_MODE_RO, false, false) != 0) return -1;
	}

	if (
	   makeSpecial("null",    AEM_MODE_RW, 1, 3) != 0
	|| makeSpecial("zero",    AEM_MODE_RO, 1, 5) != 0
	|| makeSpecial("full",    AEM_MODE_RW, 1, 7) != 0
	|| makeSpecial("random",  AEM_MODE_RO, 1, 8) != 0
	|| makeSpecial("urandom", AEM_MODE_RO, 1, 9) != 0
	) return -1;

	if (type == AEM_PROCESSTYPE_ACCOUNT) {
		if (bindMount("/var/lib/allears/Account.aem", AEM_MOUNTDIR"/Account.aem", AEM_MODE_RW, false, false) != 0) return -1;
	} else if (type == AEM_PROCESSTYPE_STORAGE) {
		if (bindMount("/var/lib/allears/Storage.aem", AEM_MOUNTDIR"/Storage.aem", AEM_MODE_RW, false, false) != 0) return -1;
		if (bindMount("/var/lib/allears/Stindex.aem", AEM_MOUNTDIR"/Stindex.aem", AEM_MODE_RW, false, false) != 0) return -1;
	}

	if (type == AEM_PROCESSTYPE_ACCOUNT || type == AEM_PROCESSTYPE_STORAGE) return 0;

	return mount(NULL, AEM_MOUNTDIR, NULL, AEM_MOUNTDIR_FLAGS | MS_REMOUNT | MS_RDONLY, tmpfs_opts);
}
