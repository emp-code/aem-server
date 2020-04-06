// HtmlCrypt.c: Encrypt index.html for All-Ears Mail
// Copy the resulting file to /etc/allears/index.html
// Compile: gcc -lsodium -lbrotlienc HtmlCrypt.c -o HtmlCrypt

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
	puts("HtmlCrypt: Encrypt index.html for All-Ears Mail");

	if (argc < 2) {puts("Terminating: Use domain as argument"); return EXIT_FAILURE;}
	if (sodium_init() < 0) {puts("Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}
	if (getKey() != 0) {puts("Terminating: Failed reading key"); return EXIT_FAILURE;}

	int fd = open("index.html", O_RDONLY);
	if (fd < 0) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed opening index.html");
		return EXIT_FAILURE;
	}

	const off_t clearBytes = lseek(fd, 0, SEEK_END);
	unsigned char *buf = malloc(clearBytes);
	const off_t readBytes = pread(fd, buf, clearBytes, 0);
	close(fd);

	if (readBytes < 1) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		free(buf);
		puts("Terminating: Failed reading index.html");
		return EXIT_FAILURE;
	}

	size_t bytes = clearBytes;
	int ret = brotliCompress(&buf, &bytes);
	if (ret != 0) {
		free(buf);
		puts("Terminating: Failed compression");
		return EXIT_FAILURE;
	}

	char headers[2048];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Connection: close\r\n"
		"Cache-Control: public, max-age=999, immutable\r\n" // ~15min
		"Content-Encoding: br\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %zu\r\n"

		"Content-Security-Policy: "
			"connect-src"     " https://%s:302/api/ data:;"
			"script-src"      " https://cdn.jsdelivr.net/gh/emp-code/ https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdn.jsdelivr.net/gh/jedisct1/libsodium.js@0.7.6/dist/browsers/sodium.js 'unsafe-eval';"
			"style-src"       " https://cdn.jsdelivr.net/gh/emp-code/;"

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
			"accelerometer"                   " 'none';"
			"ambient-light-sensor"            " 'none';"
			"autoplay"                        " 'none';"
			"battery"                         " 'none';"
			"camera"                          " 'none';"
			"display-capture"                 " 'none';"
			"document-domain"                 " 'none';"
			"document-write"                  " 'none';"
			"encrypted-media"                 " 'none';"
			"execution-while-not-rendered"    " 'none';"
			"execution-while-out-of-viewport" " 'none';"
			"fullscreen"                      " 'none';"
			"geolocation"                     " 'none';"
			"gyroscope"                       " 'none';"
			"layout-animations"               " 'none';"
			"legacy-image-formats"            " 'none';"
			"magnetometer"                    " 'none';"
			"microphone"                      " 'none';"
			"midi"                            " 'none';"
			"navigation-override"             " 'none';"
			"oversized-images"                " 'none';"
			"payment"                         " 'none';"
			"picture-in-picture"              " 'none';"
			"publickey-credentials"           " 'none';"
			"speaker"                         " 'none';"
			"sync-xhr"                        " 'none';"
			"usb"                             " 'none';"
			"vr"                              " 'none';"
			"wake-lock"                       " 'none';"
			"xr-spatial-tracking"             " 'none';"
		"\r\n"

		"Cross-Origin-Opener-Policy: same-origin\r\n"
		"Referrer-Policy: no-referrer\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-DNS-Prefetch-Control: off\r\n"
		"X-Frame-Options: deny\r\n"
		"X-XSS-Protection: 1; mode=block\r\n"
		"\r\n"
	, bytes, argv[2]);

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

	fd = open("index.html.enc", O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		puts("Terminating: Failed creating index.html.enc");
		return EXIT_FAILURE;
	}

	ret = write(fd, nonce, crypto_secretbox_NONCEBYTES);
	ret += write(fd, encrypted, lenEncrypted);
	close(fd);

	if (ret != crypto_secretbox_NONCEBYTES + lenEncrypted) {
		puts("Terminating: Failed writing index.html.enc");
		return EXIT_FAILURE;
	}

	puts("Created index.html.enc");
	return EXIT_SUCCESS;
}
