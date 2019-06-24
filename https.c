#include <string.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sodium.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/xtea.h"

#include "aem_file.h"

#include "Includes/SixBit.h"
#include "Database.h"
#include "IntMsg.h"

#include "https.h"

#define AEM_FILETYPE_CSS 1
#define AEM_FILETYPE_IMG 2
#define AEM_FILETYPE_JS  3

#define AEM_HTTPS_BUFLEN 4096
#define AEM_NETINT_BUFLEN 4096

#define AEM_NONCE_TIMEDIFF_MAX 3

// Server keypair for testing (Base64)
// Public: D00Yi5zQuaZ12UfTTu6N0RlSJzb0mP3BN91wzslJTVo=
// Secret: tCpcTrVsxFRiL8z8+g1SclyHsfX1KSmYZLIA21cHROg=
#define AEM_SERVER_SECRETKEY "\xb4\x2a\x5c\x4e\xb5\x6c\xc4\x54\x62\x2f\xcc\xfc\xfa\xd\x52\x72\x5c\x87\xb1\xf5\xf5\x29\x29\x98\x64\xb2\x0\xdb\x57\x7\x44\xe8"

#define AEM_MAXMSGTOTALSIZE 100000 // Max total size of messages to send. TODO: Move this to config

#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))

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

static void respond_https_html(mbedtls_ssl_context *ssl, const char *reqName, const struct aem_file files[], const int fileCount, const char *domain, const size_t lenDomain) {
	int reqNum = -1;

	for (int i = 0; i < fileCount; i++) {
		if (strcmp(files[i].filename, reqName) == 0) reqNum = i;
	}

	if (reqNum < 0) return;

	if (files[reqNum].lenData > 99999) return;

	char data[1091 + (lenDomain * 4) + files[reqNum].lenData];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Connection: close\r\n"
		"Content-Encoding: br\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"

		"Content-Security-Policy:"
			"connect-src"     " https://%s/web/;"
			"img-src"         " https://%s/img/;"
			"script-src"      " https://%s/js/;"
			"style-src"       " https://%s/css/;"

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
	, files[reqNum].lenData, domain, domain, domain, domain);

	size_t lenData = strlen(data);
//	printf("LenHeaders=%zd\n", lenData - AEM_LEN_DOMAIN * 4);

	memcpy(data + lenData, files[reqNum].data, files[reqNum].lenData);
	lenData += files[reqNum].lenData;
	data[lenData] = '\0';

	sendData(ssl, data, lenData);
}

// Javascript, CSS, images etc
static void respond_https_file(mbedtls_ssl_context *ssl, const char *reqName, const int fileType, const struct aem_file files[], const int fileCount) {
	int reqNum = -1;

	for (int i = 0; i < fileCount; i++) {
		if (strcmp(files[i].filename, reqName) == 0) reqNum = i;
	}

	if (reqNum < 0) return;

	char *mediatype;
	int mtLen;
	switch (fileType) {
		case AEM_FILETYPE_IMG:
			mediatype = "image/webp";
			mtLen = 10;
			break;
		case AEM_FILETYPE_JS:
			mediatype = "application/javascript; charset=utf-8";
			mtLen = 37;
			break;
		case AEM_FILETYPE_CSS:
			mediatype = "text/css; charset=utf-8";
			mtLen = 23;
			break;
		default:
			return;
	}

	char headers[205 + mtLen];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Connection: close\r\n"
		"%s"
		"Content-Type: %.*s\r\n"
		"Content-Length: %zd\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"\r\n"
	, (fileType == AEM_FILETYPE_CSS || fileType == AEM_FILETYPE_JS) ? "Content-Encoding: br\r\n" : "", mtLen, mediatype, files[reqNum].lenData);

	const size_t lenHeaders = strlen(headers);

	char data[lenHeaders + files[reqNum].lenData];
	memcpy(data, headers, lenHeaders);
	memcpy(data + lenHeaders, files[reqNum].data, files[reqNum].lenData);

	sendData(ssl, data, lenHeaders + files[reqNum].lenData);
}

// Tracking Status Resource for DNT
static void respond_https_tsr(mbedtls_ssl_context *ssl) {
	const char data[] =
	"HTTP/1.1 200 aem\r\n"
	"Tk: N\r\n"
	"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
	"Connection: close\r\n"
	"Content-Type: application/tracking-status+json\r\n"
	"Content-Length: 16\r\n"
	"\r\n"
	"{\"tracking\": \"N\"}";

	sendData(ssl, data, 195);
}

// robots.txt
static void respond_https_robots(mbedtls_ssl_context *ssl) {
	const char* data =
	"HTTP/1.1 200 aem\r\n"
	"Tk: N\r\n"
	"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
	"Connection: close\r\n"
	"Content-Type: text/plain; charset=utf-8\r\n"
	"Content-Length: 26\r\n"
	"\r\n"
	"User-agent: *\r\n"
	"Disallow: /";

	sendData(ssl, data, 197);
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

static char *userPath(const char *upk_hex, const char *filename) {
	if (upk_hex == NULL || filename == NULL) return NULL;

	char *path = malloc(75 + strlen(filename));
	if (path == NULL) return NULL;

	sprintf(path, "UserData/%.64s/%s", upk_hex, filename);
	return path;
}

static int numDigits(double number) {
	int digits = 0;
	while (number > 1) {number /= 10; digits++;}
	return digits;
}

static int getUserNonce(const unsigned char upk[crypto_box_PUBLICKEYBYTES], unsigned char nonce[24], const uint32_t clientIp, const unsigned char seed[16]) {
	char upk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
	sodium_bin2hex(upk_hex, crypto_box_PUBLICKEYBYTES * 2 + 1, upk, crypto_box_PUBLICKEYBYTES);

	char *path = userPath(upk_hex, "nonce");
	if (path == NULL) return -1;
	int fd = open(path, O_RDWR);
	if (fd < 0) {free(path); return -1;}
	if (flock(fd, LOCK_EX) != 0) {close(fd); free(path); return -1;}

	ssize_t bytesDone = read(fd, nonce, 24);
	pwrite(fd, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 24, 0);
	flock(fd, LOCK_UN);
	close(fd);
	int ret = unlink(path);
	free(path);
	if (bytesDone != 24 || ret != 0) return -1;

	memcpy(nonce, &clientIp, 4); // Box will not open if current IP differs from the one that requested the nonce

	int32_t ts;
	memcpy(&ts, nonce + 20, 4);
	const int timeDiff = (int)time(NULL) - ts;
	if (timeDiff < 0 || timeDiff > AEM_NONCE_TIMEDIFF_MAX) return - 1;

	encryptNonce(nonce, seed);
	return 0;
}

// Web login (get settings and messages)
// TODO: Support multiple pages
static void respond_https_login(mbedtls_ssl_context *ssl, const unsigned char *upk, char **decrypted, const size_t lenDecrypted) {
	if (lenDecrypted != 17 || memcmp(*decrypted, "AllEars:Web.Login", 17) != 0) {sodium_free(*decrypted); return;}
	sodium_free(*decrypted);

	char upk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
	sodium_bin2hex(upk_hex, crypto_box_PUBLICKEYBYTES * 2 + 1, upk, crypto_box_PUBLICKEYBYTES);

	unsigned char *addrData;
	unsigned char *gkData;
	uint16_t lenAddr;
	uint16_t lenGk;
	uint8_t msgCount;
	uint8_t level;

	int ret = getUserInfo(upk, &level, &addrData, &lenAddr, &gkData, &lenGk);
	if (ret != 0) return;
	unsigned char *msgData = getUserMessages(upk, &msgCount, AEM_MAXMSGTOTALSIZE);
	if (msgData == NULL) return;

	const size_t szBody = 6 + lenAddr + lenGk + AEM_MAXMSGTOTALSIZE;
	const size_t szHead = 141 + numDigits(szBody);
	const size_t szResponse = szHead + szBody;

	char data[szResponse];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Length: %zd\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, szBody);

	memcpy(data + szHead + 0, &level,    1);
	memcpy(data + szHead + 1, &msgCount, 1);
	memcpy(data + szHead + 2, &lenAddr,  2);
	memcpy(data + szHead + 4, &lenGk,    2);

	memcpy(data + szHead + 6,                   addrData, lenAddr);
	memcpy(data + szHead + 6 + lenAddr,         gkData,   lenGk);
	memcpy(data + szHead + 6 + lenAddr + lenGk, msgData,  AEM_MAXMSGTOTALSIZE);

	free(addrData);
	free(gkData);
	free(msgData);

	sendData(ssl, data, szResponse);
}

static unsigned char *addr2bin(const char *c, const size_t len) {
	if (len <= 24) return textToSixBit(c, len);
	if (len != 36) return NULL;

	// Shield addresses are encoded in hex
	for (int i = 0; i < 36; i++) {
		if (!((c[i] >= '0' && c[i] <= '9') || (c[i] >= 'a' && c[i] <= 'f'))) return NULL;
	}

	unsigned char bin[18];
	size_t binLen;
	sodium_hex2bin(bin, 18, c, 36, NULL, &binLen, NULL);
	if (binLen != 18) return NULL;
	unsigned char* binm = malloc(18);
	memcpy(binm, bin, 18);
	return binm;
}

// Message sending
static void respond_https_send(mbedtls_ssl_context *ssl, char **decrypted, const size_t lenDecrypted) {
/* Format:
	(From)\n
	(To)\n
	(Title)\n
	(Body)
*/

	const char *endFrom = strchr(*decrypted, '\n');
	if (endFrom == NULL) {sodium_free(*decrypted); return;}
	const char *endTo = strchr(endFrom + 1, '\n');
	if (endTo == NULL) {sodium_free(*decrypted); return;}

	const size_t lenFrom = endFrom - *decrypted;
	const size_t lenTo = endTo - (endFrom + 1);

	unsigned char *binFrom = addr2bin(*decrypted, lenFrom);
	if (binFrom == NULL) {sodium_free(*decrypted); return;}
	unsigned char *binTo = addr2bin(endFrom + 1, lenTo);
	if (binTo == NULL) {sodium_free(*decrypted); free(binFrom); return;}

	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	int memberLevel;
	int ret = getPublicKeyFromAddress(binTo, pk, (unsigned char*)"TestTestTestTest", &memberLevel);
	if (ret != 0) {sodium_free(*decrypted); free(binFrom); free(binTo); return;}

	unsigned char senderInfo = '\0';
	// Bits 0-1: member level
	switch(memberLevel) {
		case 3:
			BIT_SET(senderInfo, 0);
			BIT_SET(senderInfo, 1);
			break;
		case 2:
			BIT_SET(senderInfo, 1);
			break;
		case 1:
			BIT_SET(senderInfo, 0);
			break;
	}

	// Bit 7: Address type. 0 = normal, 1 = Shield
	if (lenFrom == 36) BIT_SET(senderInfo, 7);

	unsigned char *headBox = aem_intMsg_makeHeadBox(pk, senderInfo, binFrom, binTo);
	free(binFrom);
	free(binTo);

	size_t bodyLen = lenDecrypted - ((endTo + 1) - *decrypted);
	unsigned char *bodyBox = aem_intMsg_makeBodyBox(pk, endTo + 1, &bodyLen);

	sodium_free(*decrypted);

	const size_t bsLen = AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES + bodyLen + crypto_box_SEALBYTES;
	unsigned char *boxSet = malloc(bsLen);
	if (boxSet == NULL) {free(headBox); free(bodyBox); return;}

	memcpy(boxSet, headBox, AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES);
	free(headBox);
	memcpy(boxSet + AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES, bodyBox, bodyLen + crypto_box_SEALBYTES);
	free(bodyBox);

	addUserMessage(pk, boxSet, bsLen);
	free(boxSet);

	sendData(ssl,
		"HTTP/1.1 204 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 142);
}

static void respond_https_nonce(mbedtls_ssl_context *ssl, const unsigned char *post, const size_t lenPost, const uint32_t clientIp, const unsigned char seed[16]) {
	if (lenPost != crypto_box_PUBLICKEYBYTES) return;

	char upk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
	sodium_bin2hex(upk_hex, crypto_box_PUBLICKEYBYTES * 2 + 1, post, crypto_box_PUBLICKEYBYTES);

	char *path = userPath(upk_hex, "nonce");
	if (path == NULL) return;
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);

	if (fd < 0) {
		if (errno != EEXIST) {free(path); return;}

		fd = open(path, O_RDWR);
		char ts_c[4];
		pread(fd, ts_c, 4, 20);
		int32_t ts;
		memcpy(&ts, ts_c, 4);

		const int timeDiff = (int)time(NULL) - ts;
		if (timeDiff >= 0 && timeDiff < AEM_NONCE_TIMEDIFF_MAX) {
			close(fd);
			free(path);
			return;
		}
	}

	if (flock(fd, LOCK_EX) != 0) {close(fd); free(path); return;}

	// Generate nonce
	unsigned char nonce[24];
	const uint32_t ts = (uint32_t)time(NULL);
	memcpy(nonce, &clientIp, 4); // Client IP. Protection against third parties intercepting the Box.
	randombytes_buf(nonce + 4, 16);
	memcpy(nonce + 20, &ts, 4); // Timestamp. Protection against replay attacks.

	const ssize_t bytesDone = write(fd, nonce, 24);
	flock(fd, LOCK_UN);
	close(fd);
	free(path);
	if (bytesDone != 24) return;

	encryptNonce(nonce, seed);

	char data[220];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Connection: close\r\n"
		"Content-Length: 24\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"\r\n"
		"%.24s"
	, nonce);

	sendData(ssl, data, 219);
}

static char *openWebBox(const unsigned char *post, const size_t lenPost, unsigned char *upk, size_t * const lenDecrypted, const int32_t clientIp, const unsigned char seed[16]) {
	if (lenPost <= crypto_box_PUBLICKEYBYTES) return NULL;

	unsigned char nonce[24];
	if (getUserNonce(post, nonce, clientIp, seed) != 0) return NULL;

	char *decrypted = sodium_malloc(lenPost);
	if (decrypted == NULL) return NULL;

	memcpy(upk, post, crypto_box_PUBLICKEYBYTES);

	const int ret = crypto_box_open_easy((unsigned char*)decrypted, post + crypto_box_PUBLICKEYBYTES, lenPost - crypto_box_PUBLICKEYBYTES, nonce, upk, (unsigned char*)AEM_SERVER_SECRETKEY);
	if (ret != 0) {sodium_free(decrypted); return NULL;}

	sodium_mprotect_readonly(decrypted);
	*lenDecrypted = lenPost - crypto_box_PUBLICKEYBYTES - crypto_box_MACBYTES;

	return decrypted;
}

static void respond_https_addr_del(mbedtls_ssl_context *ssl, const unsigned char upk[crypto_box_PUBLICKEYBYTES], char **decrypted, const size_t lenDecrypted) {
	if (lenDecrypted < 9) {free(*decrypted); return;}
	int64_t hash;
	memcpy(&hash, *decrypted, 8);

	if (deleteAddress(upk, hash, (unsigned char*)((*decrypted) + 8), lenDecrypted - 8) != 0) return;
	sodium_free(*decrypted);

	sendData(ssl,
		"HTTP/1.1 204 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 142);
}

static void respond_https_addr_upd(mbedtls_ssl_context *ssl, const unsigned char upk[crypto_box_PUBLICKEYBYTES], char **decrypted, const size_t lenDecrypted) {
	if (lenDecrypted < 1) {free(*decrypted); return;}

	if (updateAddress(upk, (unsigned char*)(*decrypted), lenDecrypted) != 0) return;
	sodium_free(*decrypted);

	sendData(ssl,
		"HTTP/1.1 204 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 142);
}

static void respond_https_addr_add(mbedtls_ssl_context *ssl, const unsigned char upk[crypto_box_PUBLICKEYBYTES], char **decrypted, const size_t lenDecrypted) {
	unsigned char *addr;
	if (lenDecrypted == 6 && memcmp(*decrypted, "SHIELD", 6) == 0) {
		sodium_free(*decrypted);
		addr = malloc(18);
		if (addr == NULL) return;
		randombytes_buf(addr, 18);
	} else {
		addr = textToSixBit((*decrypted), lenDecrypted);
		sodium_free(*decrypted);
		if (addr == NULL) return;
	}

	const int64_t hash = addressToHash(addr, (unsigned char*)"TestTestTestTest");
	if (addAddress(upk, hash) != 0) return;

	char data[169];
	memcpy(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Length: 26\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 143);
	memcpy(data + 143, &hash, 8);
	memcpy(data + 151, addr, 18);
	free(addr);
	sendData(ssl, data, 169);
}

static void respond_https_gatekeeper(mbedtls_ssl_context *ssl, unsigned char upk[crypto_box_PUBLICKEYBYTES], char **decrypted, const size_t lenDecrypted, const unsigned char hashKey[16]) {
	int ret = updateGatekeeper(upk, *decrypted, lenDecrypted, hashKey);
	sodium_free(*decrypted);

	if (ret != 0) return;

	sendData(ssl,
		"HTTP/1.1 204 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 142);
}

static void handleRequest(mbedtls_ssl_context *ssl, const char *clientHeaders, const size_t chLen, const uint32_t clientIp, const unsigned char seed[16], const struct aem_fileSet *fileSet, const char *domain, const size_t lenDomain) {
	char* endHeaders = strstr(clientHeaders, "\r\n\r\n");
	if (endHeaders == NULL) return;
	*(endHeaders + 2) = '\0';

	char hostHeader[11 + lenDomain];
	sprintf(hostHeader, "\r\nHost: %s\r\n", domain);
	if (strstr(clientHeaders, hostHeader) == NULL) return;

	char *end = strpbrk(clientHeaders, "\r\n");
	if (memcmp(end - 9, " HTTP/1.1", 9) != 0) return;
	*(end - 9) = '\0';

	if (memcmp(clientHeaders, "GET /", 5) == 0) {
		const char *url = clientHeaders + 5;
		const size_t urlLen = (end - 9) - url;

		if (urlLen == 0) return respond_https_html(ssl, "index.html", fileSet->htmlFiles, fileSet->htmlCount, domain, lenDomain);
		if (urlLen > 5 && memcmp(url + urlLen - 5, ".html", 5) == 0) return respond_https_html(ssl, url, fileSet->htmlFiles, fileSet->htmlCount, domain, lenDomain);

		if (urlLen == 15 && memcmp(url, ".well-known/dnt", 15) == 0) return respond_https_tsr(ssl);
		if (urlLen == 10 && memcmp(url, "robots.txt",      10) == 0) return respond_https_robots(ssl);

		if (urlLen  >  4 && memcmp(url, "css/", 4) == 0) return respond_https_file(ssl, url + 4, AEM_FILETYPE_CSS, fileSet->cssFiles, fileSet->cssCount);
		if (urlLen  >  4 && memcmp(url, "img/", 4) == 0) return respond_https_file(ssl, url + 4, AEM_FILETYPE_IMG, fileSet->imgFiles, fileSet->imgCount);
		if (urlLen  >  3 && memcmp(url, "js/",  3) == 0) return respond_https_file(ssl, url + 3, AEM_FILETYPE_JS,  fileSet->jsFiles,  fileSet->jsCount);
	} else if (memcmp(clientHeaders, "POST /", 6) == 0) {
		const char *url = clientHeaders + 6;
		const size_t urlLen = (end - 9) - url;
		const char *post = endHeaders + 4;
		const size_t lenPost = chLen - (post - clientHeaders);

		if (urlLen == 9 && memcmp(url, "web/nonce", 9) == 0) return respond_https_nonce(ssl, (unsigned char*)post, lenPost, clientIp, seed);

		if (urlLen < 5) return;
		unsigned char upk[crypto_box_PUBLICKEYBYTES];
		size_t lenDecrypted;
		char *decrypted = openWebBox((unsigned char*)post, lenPost, upk, &lenDecrypted, clientIp, seed);
		if (decrypted == NULL) return;

		if (urlLen == 9 && memcmp(url, "web/login", 9) == 0) return respond_https_login(ssl, upk, &decrypted, lenDecrypted);
		if (urlLen == 8 && memcmp(url, "web/send", 8) == 0) return respond_https_send(ssl, &decrypted, lenDecrypted);

		if (urlLen == 12 && memcmp(url, "web/addr/del", 12) == 0) return respond_https_addr_del(ssl, upk, &decrypted, lenDecrypted);
		if (urlLen == 12 && memcmp(url, "web/addr/add", 12) == 0) return respond_https_addr_add(ssl, upk, &decrypted, lenDecrypted);
		if (urlLen == 12 && memcmp(url, "web/addr/upd", 12) == 0) return respond_https_addr_upd(ssl, upk, &decrypted, lenDecrypted);

		if (urlLen == 14 && memcmp(url, "web/gatekeeper", 14) == 0) return respond_https_gatekeeper(ssl, upk, &decrypted, lenDecrypted, (unsigned char*)"TestTestTestTest");
	}
}

int respond_https(int sock, mbedtls_x509_crt *srvcert, mbedtls_pk_context *pkey, const uint32_t clientIp, const unsigned char seed[16], const struct aem_fileSet *fileSet, const char *domain, const size_t lenDomain) {
	// Setting up the SSL
	mbedtls_ssl_config conf;
	mbedtls_ssl_config_init(&conf);

	int ret;
	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		printf( "Failed; mbedtls_ssl_config_defaults returned %d\n\n", ret);
	}

	// Seed the RNG
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16)) != 0) {
		printf( "ERROR: mbedtls_ctr_drbg_seed returned %d\n", ret);
		return -1;
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_ssl_conf_ca_chain(&conf, srvcert->next, NULL);
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, srvcert, pkey)) != 0) {
		printf("ERROR: mbedtls_ssl_conf_own_cert returned %d\n", ret);
		return -1;
	}

	mbedtls_ssl_context ssl;
	mbedtls_ssl_init(&ssl);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		printf( "ERROR: mbedtls_ssl_setup returned %d\n", ret);
		return -1;
	}

	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	// Handshake
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			char error_buf[100];
			mbedtls_strerror(ret, error_buf, 100);
			printf( "ERROR: mbedtls_ssl_handshake returned %d: %s\n", ret, error_buf);
			mbedtls_ssl_free(&ssl);
			return -1;
		}
	}

	unsigned char req[AEM_HTTPS_BUFLEN + 1];
	bzero(req, AEM_HTTPS_BUFLEN);

	// Read request
	do {ret = mbedtls_ssl_read(&ssl, req, AEM_HTTPS_BUFLEN);}
		while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret > 0) {
		handleRequest(&ssl, (char*)req, ret, clientIp, seed, fileSet, domain, lenDomain);
	} else if (ret < 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY && ret != MBEDTLS_ERR_SSL_CONN_EOF && ret != MBEDTLS_ERR_NET_CONN_RESET) {
		// Failed to read request
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		printf("ERROR: Incoming connection failed: %d: %s\n", ret, error_buf);
	}

	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ssl_free(&ssl);
	return 0;
}
