#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/GetKey.h"

#include "../Common/LoadEnc.h"

int loadEnc(const char * const path, const size_t lenTarget, unsigned char * const target) {
	const int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	off_t readBytes = read(fd, nonce, crypto_secretbox_NONCEBYTES);
	if (readBytes != crypto_secretbox_NONCEBYTES) {close(fd); return -1;}

	unsigned char encrypted[lenTarget + crypto_secretbox_MACBYTES];
	readBytes = read(fd, encrypted, lenTarget + crypto_secretbox_MACBYTES);
	close(fd);
	if (readBytes != (off_t)lenTarget + crypto_secretbox_MACBYTES) return -1;

	unsigned char master[crypto_secretbox_KEYBYTES];
	if (getKey(master) != 0) {fputs("Failed reading key\n", stderr); return -1;}

	const int ret = crypto_secretbox_open_easy(target, encrypted, crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	return ret;
}
