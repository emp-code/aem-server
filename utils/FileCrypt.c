// FileCrypt.c: Encrypt files for All-Ears Mail
// Place resulting files in /etc/allears (remove the .enc extension)
// Compile: gcc -lsodium -lbrotlienc FileCrypt.c -o FileCrypt

#include <ctype.h> // for isxdigit
#include <fcntl.h> // for open
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h> // for write

#include "../Global.h"

#include "../Common/Brotli.c"

static unsigned char master[crypto_secretbox_KEYBYTES];

static void toggleEcho(const bool on) {
	struct termios t;
	if (tcgetattr(STDIN_FILENO, &t) != 0) return;

	if (on) {
		t.c_lflag |= ((tcflag_t)ECHO);
		t.c_lflag |= ((tcflag_t)ICANON);
	} else {
		t.c_lflag &= ~((tcflag_t)ECHO);
		t.c_lflag &= ~((tcflag_t)ICANON);
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

static int getKey(void) {
	toggleEcho(false);

	puts("Enter Master Key (hex) - will not echo");

	char masterHex[crypto_secretbox_KEYBYTES * 2];
	for (unsigned int i = 0; i < crypto_secretbox_KEYBYTES * 2; i++) {
		const int gc = getchar();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		masterHex[i] = gc;
	}

	toggleEcho(true);

	sodium_hex2bin(master, crypto_secretbox_KEYBYTES, masterHex, crypto_secretbox_KEYBYTES * 2, NULL, NULL, NULL);
	sodium_memzero(masterHex, crypto_secretbox_KEYBYTES * 2);
	return 0;
}

int main(int argc, char *argv[]) {
	puts("allears-encrypt: Encrypt files for All-Ears Mail");

	if (argc < 2) {puts("Terminating: Use filename as parameter"); return EXIT_FAILURE;}
	if (sodium_init() < 0) {puts("Terminating: Failed to initialize libsodium"); return EXIT_FAILURE;}
	if (getKey() != 0) {puts("Terminating: Key input failed"); return EXIT_FAILURE;}

	int fileType;
	if (strcmp(argv[1], "index.html") == 0) fileType = AEM_FILETYPE_HTM;
	else if (strcmp(argv[1], "main.css") == 0) fileType = AEM_FILETYPE_CSS;
	else if (strcmp(argv[1], "all-ears.js") == 0) fileType = AEM_FILETYPE_JSA;
	else if (strcmp(argv[1], "main.js") == 0) fileType = AEM_FILETYPE_JSM;
	else {puts("Terminating: Unsupported file"); return EXIT_FAILURE;}

	if (fileType == AEM_FILETYPE_HTM && argc < 3) {puts("Terminating: Need domain as second argument"); return EXIT_FAILURE;}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed to open file");
		return EXIT_FAILURE;
	}

	const off_t clearBytes = lseek(fd, 0, SEEK_END);
	unsigned char *buf = malloc(clearBytes);
	off_t readBytes = pread(fd, buf, clearBytes, 0);
	close(fd);

	if (readBytes < 1) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed to read file");
		return EXIT_FAILURE;
	}

	size_t bytes = clearBytes;
	int ret = brotliCompress(&buf, &bytes);
	if (ret != 0) {
		free(buf);
		puts("Terminating: Failed to compress");
		return EXIT_FAILURE;
	}

	char headers[2000];
	switch (fileType) {
		case AEM_FILETYPE_CSS:
			sprintf(headers,
				"HTTP/1.1 200 aem\r\n"
				"Tk: N\r\n"
				"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
				"Expect-CT: enforce; max-age=99999999\r\n"
				"Connection: close\r\n"
				"Cache-Control: public, max-age=999, immutable\r\n" // ~15min
				"Content-Encoding: br\r\n"
				"Content-Type: text/css; charset=utf-8\r\n"
				"Content-Length: %zd\r\n"
				"X-Content-Type-Options: nosniff\r\n"
				"X-Robots-Tag: noindex\r\n"
				"Cross-Origin-Resource-Policy: same-origin\r\n"
				"\r\n"
			, bytes);
		break;

		case AEM_FILETYPE_JSA:
		case AEM_FILETYPE_JSM:
			sprintf(headers,
				"HTTP/1.1 200 aem\r\n"
				"Tk: N\r\n"
				"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
				"Expect-CT: enforce; max-age=99999999\r\n"
				"Connection: close\r\n"
				"Cache-Control: public, max-age=999, immutable\r\n" // ~15min
				"Content-Encoding: br\r\n"
				"Content-Type: application/javascript; charset=utf-8\r\n"
				"Content-Length: %zd\r\n"
				"X-Content-Type-Options: nosniff\r\n"
				"X-Robots-Tag: noindex\r\n"
				"Cross-Origin-Resource-Policy: same-origin\r\n"
				"\r\n"
			, bytes);
		break;

		default: // HTML
			sprintf(headers,
				"HTTP/1.1 200 aem\r\n"
				"Tk: N\r\n"
				"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
				"Expect-CT: enforce; max-age=99999999\r\n"
				"Connection: close\r\n"
				"Cache-Control: public, max-age=999, immutable\r\n" // ~15min
				"Content-Encoding: br\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"Content-Length: %zd\r\n"

				"Content-Security-Policy: "
					"connect-src"     " https://%s:302/api/;"
					"script-src"      " https://%s/files/main.js https://%s/files/all-ears.js https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdnjs.cloudflare.com/ajax/libs/js-nacl/1.3.2/nacl_factory.min.js;"
					"style-src"       " https://%s/files/main.css;"

					"base-uri"        " 'none';"
					"child-src"       " 'none';"
					"default-src"     " 'none';"
					"font-src"        " 'none';"
					"form-action"     " 'none';"
					"frame-ancestors" " 'none';"
					"frame-src"       " 'none';"
					"img-src"         " 'none';"
					"manifest-src"    " 'none';"
					"media-src"       " 'none';"
					"object-src"      " 'none';"
					"prefetch-src"    " 'none';"
					"worker-src"      " 'none';"

					"block-all-mixed-content;"
					"sandbox allow-scripts allow-same-origin;"
				"\r\n"

				"Feature-Policy: "
					"accelerometer"        " 'none';"
					"ambient-light-sensor" " 'none';"
					"autoplay"             " 'none';"
					"battery"              " 'none';"
					"camera"               " 'none';"
					"display-capture"      " 'none';"
					"document-domain"      " 'none';"
					"document-write"       " 'none';"
					"encrypted-media"      " 'none';"
					"fullscreen"           " 'none';"
					"geolocation"          " 'none';"
					"gyroscope"            " 'none';"
					"magnetometer"         " 'none';"
					"microphone"           " 'none';"
					"midi"                 " 'none';"
					"payment"              " 'none';"
					"picture-in-picture"   " 'none';"
					"speaker"              " 'none';"
					"sync-xhr"             " 'none';"
					"usb"                  " 'none';"
					"vr"                   " 'none';"
					"xr-spatial-tracking"  " 'none';"
				"\r\n"

				"Referrer-Policy: no-referrer\r\n"
				"X-Content-Type-Options: nosniff\r\n"
				"X-Frame-Options: deny\r\n"
				"X-XSS-Protection: 1; mode=block\r\n"
				"\r\n"
			, bytes, argv[2], argv[2], argv[2], argv[2]);
	}

	const size_t lenHeaders = strlen(headers);
	unsigned char final[lenHeaders + bytes];
	memcpy(final, headers, lenHeaders);
	memcpy(final + lenHeaders, buf, bytes);
	bytes += lenHeaders;

	const size_t lenEncrypted = bytes + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted, final, bytes, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);

	char path[strlen(argv[1]) + 5];
	sprintf(path, "%s.enc", argv[1]);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		printf("Terminating: Failed to create %s\n", path);
		return EXIT_FAILURE;
	}

	ret = write(fd, nonce, crypto_secretbox_NONCEBYTES);
	ret += write(fd, encrypted, lenEncrypted);
	close(fd);

	if (ret != crypto_secretbox_NONCEBYTES + lenEncrypted) {
		printf("Failed to write %s\n", path);
		return EXIT_FAILURE;
	}

	printf("Created %s\n", path);
	return EXIT_SUCCESS;
}