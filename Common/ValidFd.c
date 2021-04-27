#include <sys/types.h>
#include <sys/stat.h>

#include "ValidFd.h"

bool validFd(const int fd) {
	struct stat fileStat;

	return (
	   fstat(fd, &fileStat) == 0
	&& (fileStat.st_mode & S_IFMT) == S_IFREG
	&& fileStat.st_nlink == 1 // Hard link count
	&& fileStat.st_gid == 0
	&& fileStat.st_uid == 0
	);
}
