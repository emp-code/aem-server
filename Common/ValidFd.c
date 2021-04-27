#include <sys/types.h>
#include <sys/stat.h>

#include "ValidFd.h"

bool validFd(const int fd, const unsigned int fileType) {
	struct stat fileStat;

	return (
	   fstat(fd, &fileStat) == 0
	&& (fileStat.st_mode & S_IFMT) == fileType
	&& fileStat.st_nlink == 1 // Hard link count
	&& fileStat.st_gid == 0
	&& fileStat.st_uid == 0
	);
}
