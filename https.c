#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/xtea.h"

#include "crypto_box.h"

#include "defines.h"
#include "Includes/Base64.h"

#include "https.h"

#define AEM_FILETYPE_JS 1
#define AEM_FILETYPE_CSS 2

#define AEM_HTTPS_BUFLEN 1000
#define AEM_NETINT_BUFLEN 1000

#define AEM_NONCE_TIMEDIFF_MAX 30

#define AEM_SERVER_SECRETKEY_TEMP_B64 "WEPFgMoessUEVWiXJ0RUX0EjpKVmN9nNBvWIKLO2+/4="

static void sendData(mbedtls_ssl_context* ssl, const char* data, const size_t lenData) {
	size_t sent = 0;

	while (sent < lenData) {
		int ret;
		do {ret = mbedtls_ssl_write(ssl, (unsigned char*)(data + sent), (lenData - sent > AEM_NETINT_BUFLEN) ? AEM_NETINT_BUFLEN : lenData - sent);}
		while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

		if (ret < 0) {
			printf("ERROR: Failed transfer: %d\n", ret);
			return;
		}

		sent += ret;
	}
}

static void respond_https_home(mbedtls_ssl_context *ssl) {
	int fd = open("aem-web.html", O_RDONLY);
	if (fd < 0) return;

	const size_t lenHtml = lseek(fd, 0, SEEK_END);
	if (lenHtml < 10 || lenHtml > 99999) {close(fd); return;}

	char headers[1050 + AEM_LEN_DOMAIN * 4];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"

		"Content-Security-Policy:"
			"connect-src"     " https://"AEM_DOMAIN"/web/;"
			"img-src"         " https://"AEM_DOMAIN"/img/;"
			"script-src"      " https://"AEM_DOMAIN"/js/;"
			"style-src"       " https://"AEM_DOMAIN"/css/;"

			"base-uri"        " 'none';"
			"child-src"       " 'none';"
			"default-src"     " 'none';"
			"font-src"        " 'none';"
			"form-action"     " 'none';"
			"frame-ancestors" " 'none';"
			"frame-src"       " 'none';"
			"manifest-src"    " 'none';"
			"media-src"       " 'none';"
			"navigate-to"     " 'none';" // Use * to allow links
			"object-src"      " 'none';"
			"prefetch-src"    " 'none';"
			"worker-src"      " 'none';"

			"block-all-mixed-content;"
			"sandbox allow-scripts;"
		"\r\n"

		"Feature-Policy:"
			"autoplay"             " 'none';"
			"accelerometer"        " 'none';"
			"ambient-light-sensor" " 'none';"
			"camera"               " 'none';"
			"cookie"               " 'none';"
			"display-capture"      " 'none';"
			"document-domain"      " 'none';"
			"docwrite"             " 'none';"
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
		"\r\n"

		"Referrer-Policy: no-referrer\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-XSS-Protection: 1; mode=block\r\n"
		"\r\n"
	, lenHtml);
	const size_t lenHeaders = strlen(headers);
//	printf("LenHeaders=%zd\n", lenHeaders - AEM_LEN_DOMAIN * 4);

	char data[lenHeaders + lenHtml];
	memcpy(data, headers, lenHeaders);

	const int bytesRead = pread(fd, data + lenHeaders, lenHtml, 0);
	close(fd);

	if (bytesRead != lenHtml) return;

	sendData(ssl, data, lenHeaders + lenHtml);
}

// Javascript, CSS, images etc
static void respond_https_file(mbedtls_ssl_context *ssl, const char *path, const int fileType) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) return;

	const size_t lenFile = lseek(fd, 0, SEEK_END);
	if (lenFile < 10 || lenFile > 99999) {close(fd); return;}
	lseek(fd, 0, SEEK_SET);

	char *mediatype;
	int mtLen;
	switch (fileType) {
		case AEM_FILETYPE_JS:
			mediatype = "application/javascript; charset=utf-8";
			mtLen = 37;
			break;
		case AEM_FILETYPE_CSS:
			mediatype = "text/css; charset=utf-8";
			mtLen = 23;
			break;
	}

	char headers[164 + mtLen];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Type: %.*s\r\n"
		"Content-Length: %zd\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"\r\n"
	, mtLen, mediatype, lenFile);

	const size_t lenHeaders = strlen(headers);

	char data[lenHeaders + lenFile];
	memcpy(data, headers, lenHeaders);
	const int bytesRead = read(fd, data + lenHeaders, lenFile);
	close(fd);
	if (bytesRead != lenFile) return;

	sendData(ssl, data, lenHeaders + lenFile);
}

// Tracking Status Resource for DNT
static void respond_https_tsr(mbedtls_ssl_context *ssl) {
	const char* data =
	"HTTP/1.1 200 aem\r\n"
	"Tk: N\r\n"
	"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
	"Content-Type: application/tracking-status+json\r\n"
	"Content-Length: 16\r\n"
	"\r\n"
	"{\"tracking\":\"N\"}";

	sendData(ssl, data, 175);
}

// robots.txt
static void respond_https_robots(mbedtls_ssl_context *ssl) {
	const char* data =
	"HTTP/1.1 200 aem\r\n"
	"Tk: N\r\n"
	"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
	"Content-Type: text/plain; charset=utf-8\r\n"
	"Content-Length: 26\r\n"
	"\r\n"
	"User-agent: *\r\n"
	"Disallow: /";

	sendData(ssl, data, 178);
}

static void encryptNonce(unsigned char nonce[24], const unsigned char seed[16]) {
	// Nonce is encrypted to protect against leaking server time etc
	// One-way encryption (hashing) would work, but TEA guarantees no collision risk
	mbedtls_xtea_context tea;
	mbedtls_xtea_init(&tea);
	mbedtls_xtea_setup(&tea, seed);

	unsigned char nonce_encrypted[24];
	mbedtls_xtea_crypt_ecb(&tea, MBEDTLS_XTEA_ENCRYPT, nonce, nonce_encrypted); // Bytes 1-8
	mbedtls_xtea_crypt_ecb(&tea, MBEDTLS_XTEA_ENCRYPT, nonce + 8, nonce_encrypted + 8); // Bytes 9-16
	mbedtls_xtea_crypt_ecb(&tea, MBEDTLS_XTEA_ENCRYPT, nonce + 16, nonce_encrypted + 16); // Bytes 17-24
	memcpy(nonce, nonce_encrypted, 24);
}

static void noncePath(char path[60], const char *b64_upk) {
	memcpy(path, "UserData/", 9);

	for (int i = 0; i < 44; i++) {
		if (b64_upk[i] == '/')
			path[9 + i] = '-';
		else
			path[9 + i] = b64_upk[i];
	}

	memcpy(path + 53, "/nonce\0", 7);
}

// Web login
static void respond_https_login(mbedtls_ssl_context *ssl, const char *url, const size_t lenUrl, const uint32_t clientIp, const unsigned char seed[16]) {
	const char *b64_upk = url + 10;
	char* end = strchr(b64_upk, '.');
	if (end == NULL) return;
	const size_t b64_upk_len = end - b64_upk;
	if (b64_upk_len != 44) return;

	// Get nonce
	char path[60];
	noncePath(path, b64_upk);

	int fd = open(path, O_RDONLY);
	unsigned char nonce[24];
	ssize_t bytesDone = read(fd, nonce, 24);
	close(fd);
	if (bytesDone != 24) return;

	memcpy(nonce, &clientIp, 4); // Box will not open if current IP differs from the one that requested the nonce

	int32_t ts;
	memcpy(&ts, nonce + 20, 4);
	int timeDiff = (int)time(NULL) - ts;
	if (timeDiff < 0 || timeDiff > AEM_NONCE_TIMEDIFF_MAX) return;

	encryptNonce(nonce, seed);

	// Prepare to open Box
	const char *b64_bd = end + 1;
	const size_t b64_bd_len = (url + lenUrl) - b64_bd;

	size_t userPkLen = 0, boxDataLen = 0;
	unsigned char *userPk = b64Decode((unsigned char*)b64_upk, b64_upk_len, &userPkLen);
	unsigned char *boxData = b64Decode((unsigned char*)b64_bd, b64_bd_len, &boxDataLen);

	if (userPk == NULL || boxData == NULL || userPkLen != 32 || boxDataLen != 33) {
		if (userPk != NULL) free(userPk);
		if (boxData != NULL) free(boxData);
		return;
	}

	// First crypto_box_BOXZEROBYTES of boxData need to be 0x00
	unsigned char box[crypto_box_BOXZEROBYTES + boxDataLen];
	bzero(box, crypto_box_BOXZEROBYTES);
	memcpy(box + crypto_box_BOXZEROBYTES, boxData, boxDataLen);

	size_t skeyLen;
	unsigned char *skey = b64Decode((unsigned char*)AEM_SERVER_SECRETKEY_TEMP_B64, strlen(AEM_SERVER_SECRETKEY_TEMP_B64), &skeyLen);
	if (skey == NULL || skeyLen != 32) {
		if (skey != NULL) free(skey);
		if (userPk != NULL) free(userPk);
		if (boxData != NULL) free(boxData);
		return;
	}

	// Open the Box
	unsigned char decrypted[boxDataLen + crypto_box_BOXZEROBYTES];
	const int ret = crypto_box_open(decrypted, box, boxDataLen + crypto_box_BOXZEROBYTES, nonce, userPk, skey);

	free(skey);
	free(userPk);
	free(boxData);

	if (ret != 0 || strncmp((char*)(decrypted + crypto_box_ZEROBYTES), "AllEars:Web.Login", 17) != 0) return;

	// Login successful

	const char* data =
	"HTTP/1.1 200 aem\r\n"
	"Tk: N\r\n"
	"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
	"Content-Type: text/plain; charset=utf-8\r\n"
	"Content-Length: 4\r\n"
	"Access-Control-Allow-Origin: *\r\n"
	"\r\n"
	"TODO";

	sendData(ssl, data, strlen(data));
}

// Request for a nonce to be used with a NaCl Box. URL format: name.tld/web/nonce/public-key-in-base64
static void respond_https_nonce(mbedtls_ssl_context *ssl, const char *b64_upk, const uint32_t clientIp, const unsigned char seed[16]) {
	int fd = open("/dev/urandom", O_RDONLY);
	unsigned char nonce_random[16];
	ssize_t bytesDone = read(fd, nonce_random, 16);
	close(fd);
	if (bytesDone != 16) return;

	unsigned char nonce[24];

	const uint32_t ts = (uint32_t)time(NULL);
	memcpy(nonce, &clientIp, 4); // Client IP. Protection against third parties intercepting the Box.
	memcpy(nonce + 4, nonce_random, 16);
	memcpy(nonce + 20, &ts, 4); // Timestamp. Protection against replay attacks.

// Store nonce in user folder
	char path[60];
	noncePath(path, b64_upk);

	fd = open(path, O_WRONLY | O_TRUNC);
	bytesDone = write(fd, nonce, 24);
	close(fd);
	if (bytesDone != 24) return;

	encryptNonce(nonce, seed);

	// Send Base64-ecnoded nonce to client
	size_t b64_nonceLen;
	unsigned char *b64_nonce = b64Encode(nonce, 24, &b64_nonceLen);
	if (b64_nonceLen != 32) return;

//	char data[185 + 32];
	char data[185 + 32 + 32];

	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"\r\n%.*s"
	, b64_nonceLen, 32, b64_nonce);
	free(b64_nonce);

	sendData(ssl, data, 185 + 32 + 32);
//	sendData(ssl, data, 185 + 32);
}

static void handleRequest(mbedtls_ssl_context *ssl, const char *clientHeaders, const size_t chLen, const uint32_t clientIp, const unsigned char seed[16]) {
	if (chLen < 14 || memcmp(clientHeaders, "GET /", 5) != 0) return;

	char* end = strpbrk(clientHeaders + 5, "\r\n");
	if (end == NULL) return;

	if (memcmp(end - 9, " HTTP/1.1", 9) != 0) return;
	*(end - 9) = '\0';

	const size_t urlLen = end - clientHeaders - 14; // 5 + 9
	const char *url = clientHeaders + 5;

	if (urlLen == 0) return respond_https_home(ssl); // GET / HTTP/1.1
	if (urlLen == 15 && memcmp(clientHeaders + 5, ".well-known/dnt", 15) == 0) return respond_https_tsr(ssl);
	if (urlLen == 10 && memcmp(clientHeaders + 5, "robots.txt",      10) == 0) return respond_https_robots(ssl);
	if (urlLen > 3 && memcmp(clientHeaders + 5, "js/", 3) == 0) return respond_https_file(ssl, url, AEM_FILETYPE_JS);
	if (urlLen > 4 && memcmp(clientHeaders + 5, "css/", 4) == 0) return respond_https_file(ssl, url, AEM_FILETYPE_CSS);
	if (urlLen > 10 && memcmp(clientHeaders + 5, "web/login/", 10) == 0) return respond_https_login(ssl, url, urlLen, clientIp, seed);
	if (urlLen == 54 && memcmp(clientHeaders + 5, "web/nonce/", 10) == 0) return respond_https_nonce(ssl, url + 10, clientIp, seed);
}

void respond_https(mbedtls_ssl_context *ssl, const uint32_t clientIp, const unsigned char seed[16]) {
	unsigned char req[AEM_HTTPS_BUFLEN + 1];
	bzero(req, AEM_HTTPS_BUFLEN);

	int ret;
	do {ret = mbedtls_ssl_read(ssl, req, AEM_HTTPS_BUFLEN);}
		while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret > 0) return handleRequest(ssl, (char*)req, ret, clientIp, seed);

	// Failed to read request
	if (ret != 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY && ret != MBEDTLS_ERR_SSL_CONN_EOF && ret != MBEDTLS_ERR_NET_CONN_RESET) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		printf( "ERROR: Incoming connection failed: %d: %s\n", ret, error_buf);
	}
}
