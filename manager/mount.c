#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <syslog.h>
#include <unistd.h>

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

static int bindMount(const char * const source, const char * const target, const bool readOnly, const bool allowExec, const bool isDir) {
	if (isDir) {
		if (mkdir(target, 0) != 0) return -1;
	} else {
		if (mknod(target, S_IFREG, 0) != 0) return -1;
	}

	if (
	   mount(source, target, NULL, MS_BIND, "") != 0
	|| mount("",     target, "",   MS_UNBINDABLE, "") != 0
	) return -1;

	unsigned long mountFlags = MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOATIME | MS_SILENT;

	if (!allowExec)
		mountFlags |= MS_NOEXEC;

	if (readOnly)
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

	int nr_inodes, fsmode;
	switch (type) {
		case AEM_PROCESSTYPE_MTA: fsmode = 1550; nr_inodes = 14; break;
		case AEM_PROCESSTYPE_API: fsmode = 1550; nr_inodes = 14; break;
		case AEM_PROCESSTYPE_WEB: fsmode = 1550; nr_inodes = 13; break;
		case AEM_PROCESSTYPE_ACCOUNT: fsmode = 1770; nr_inodes = 14; break;
		case AEM_PROCESSTYPE_STORAGE: fsmode = 1770; nr_inodes = 15; break;
		case AEM_PROCESSTYPE_ENQUIRY: fsmode = 1550; nr_inodes = 14; break;
		default: return -1;
	}

	char tmpfs_opts[512];
	sprintf(tmpfs_opts, "size=1,uid=0,gid=%d,mode=%d,nr_inodes=%d", aemGroup, fsmode, nr_inodes);

	if (mount("tmpfs", AEM_MOUNTDIR, "tmpfs", AEM_MOUNTDIR_FLAGS, tmpfs_opts) != 0) return -1;
	if (mount("", AEM_MOUNTDIR, "", MS_UNBINDABLE, "") != 0) return -1;

	if (
	   mkdir(AEM_MOUNTDIR"/dev",     AEM_MODE_XO) != 0
	|| mkdir(AEM_MOUNTDIR"/usr",     AEM_MODE_XO) != 0
	|| chown(AEM_MOUNTDIR"/dev",     0, aemGroup) != 0
	|| chown(AEM_MOUNTDIR"/usr",     0, aemGroup) != 0
	) return -1;

	if (
	   bindMount("/lib",       AEM_MOUNTDIR"/lib",       true, true, true) != 0
	|| bindMount("/lib64",     AEM_MOUNTDIR"/lib64",     true, true, true) != 0
	|| bindMount("/usr/lib",   AEM_MOUNTDIR"/usr/lib",   true, true, true) != 0
	|| bindMount("/usr/lib64", AEM_MOUNTDIR"/usr/lib64", true, true, true) != 0
	) return -1;

	if ((type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_ENQUIRY) && (
	   bindMount("/usr/share/ca-certificates/mozilla/", AEM_MOUNTDIR"/ssl-certs", true, false, true) != 0
	)) return -1;

	if (bindMount("/dev/log", AEM_MOUNTDIR"/dev/log", false, false, false) != 0) return -1;

	if (type == AEM_PROCESSTYPE_MTA) {
		if (bindMount(AEM_HOMEDIR"/GeoLite2-Country.mmdb", AEM_MOUNTDIR"/GeoLite2-Country.mmdb", true, false, false) != 0) return -1;
	}

	if (
	   makeSpecial("null",    AEM_MODE_RW, 1, 3) != 0
	|| makeSpecial("zero",    AEM_MODE_RO, 1, 5) != 0
	|| makeSpecial("full",    AEM_MODE_RW, 1, 7) != 0
	|| makeSpecial("random",  AEM_MODE_RO, 1, 8) != 0
	|| makeSpecial("urandom", AEM_MODE_RO, 1, 9) != 0
	) return -1;

	if (type == AEM_PROCESSTYPE_ACCOUNT) {
		if (bindMount(AEM_HOMEDIR"/Account.aem", AEM_MOUNTDIR"/Account.aem", false, false, false) != 0) return -1;
	} else if (type == AEM_PROCESSTYPE_STORAGE) {
		if (bindMount(AEM_HOMEDIR"/Storage.aem", AEM_MOUNTDIR"/Storage.aem", false, false, false) != 0) return -1;
		if (bindMount(AEM_HOMEDIR"/Stindex.aem", AEM_MOUNTDIR"/Stindex.aem", false, false, false) != 0) return -1;
	}

	if (type == AEM_PROCESSTYPE_ACCOUNT || type == AEM_PROCESSTYPE_STORAGE) return 0;

	return mount(NULL, AEM_MOUNTDIR, NULL, AEM_MOUNTDIR_FLAGS | MS_REMOUNT | MS_RDONLY, tmpfs_opts);
}
