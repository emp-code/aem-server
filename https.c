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
#include "defines.h"

#include "Includes/Base64.h"
#include "Includes/SixBit.h"
#include "Database.h"
#include "IntMsg.h"

#include "https.h"

#define AEM_FILETYPE_CSS 1
#define AEM_FILETYPE_IMG 2
#define AEM_FILETYPE_JS  3

#define AEM_HTTPS_BUFLEN 1000
#define AEM_NETINT_BUFLEN 1000

#define AEM_NONCE_TIMEDIFF_MAX 30

#define AEM_SERVER_KEY_SEED "TestServer0123456789012345678901"

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

static void respond_https_html(mbedtls_ssl_context *ssl, const char *reqName, const struct aem_file files[], const int fileCount) {
	int reqNum = -1;

	for (int i = 0; i < fileCount; i++) {
		if (strcmp(files[i].filename, reqName) == 0) reqNum = i;
	}

	if (reqNum < 0) return;

	if (files[reqNum].lenData > 99999) return;

	char data[1091 + AEM_LEN_DOMAIN * 4 + files[reqNum].lenData];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Connection: close\r\n"
		"Content-Encoding: br\r\n"
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
	, files[reqNum].lenData);

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
	if (filename == NULL) return NULL;

	char *path = malloc(76 + strlen(filename));
	if (path == NULL) return NULL;

	sprintf(path, "UserData/%.64s/%s", upk_hex, filename);
	return path;
}

char *loadUserAddressList(const char *b64_upk, const char *filename, int *count) {
	char *path = userPath(b64_upk, filename);
	if (path == NULL) return NULL;
	const int fd = open(path, O_RDONLY);
	if (fd < 0) {free(path); return NULL;}

	const off_t sz = lseek(fd, 0, SEEK_END);
	if (sz % 16 != 0) {close(fd); free(path); return NULL;}

	char *data = malloc(sz);
	if (data == NULL) {close(fd); free(path); return NULL;}
	const ssize_t bytesDone = pread(fd, data, sz, 0);
	close(fd);
	free(path);

	if (bytesDone != sz) {free(data); return NULL;}

	*count = sz / 16;
	return data;
}

static int numDigits(double number) {
	int digits = 0;
	while (number > 1) {number /= 10; digits++;}
	return digits;
}

// Web login
static void respond_https_login(mbedtls_ssl_context *ssl, const unsigned char *post, const size_t postLen, const uint32_t clientIp, const unsigned char seed[16]) {
	if (postLen != 65) return; // 32 + 33

	char upk_hex[65];
	sodium_bin2hex(upk_hex, 65, post, 32);

	// Get nonce
	char *path = userPath(upk_hex, "nonce");
	if (path == NULL) return;
	int fd = open(path, O_RDONLY);
	if (fd < 0) {free(path); return;}
	if (flock(fd, LOCK_EX) != 0) {close(fd); free(path); return;}

	unsigned char nonce[24];
	ssize_t bytesDone = read(fd, nonce, 24);
	flock(fd, LOCK_UN);
	close(fd);
	int ret = unlink(path);
	free(path);
	if (bytesDone != 24 || ret != 0) return;

	memcpy(nonce, &clientIp, 4); // Box will not open if current IP differs from the one that requested the nonce

	int32_t ts;
	memcpy(&ts, nonce + 20, 4);
	const int timeDiff = (int)time(NULL) - ts;
	if (timeDiff < 0 || timeDiff > AEM_NONCE_TIMEDIFF_MAX) return;

	encryptNonce(nonce, seed);

	unsigned char *pkServer = malloc(32); if (pkServer == NULL) return;
	unsigned char *skServer = malloc(32); if (skServer == NULL) return;
	crypto_box_seed_keypair(pkServer, skServer, (unsigned char*)AEM_SERVER_KEY_SEED);
	free(pkServer);

	// Open the Box
	unsigned char decrypted[18];
	ret = crypto_box_open_easy(decrypted, post + 32, 33, nonce, post, skServer);
	free(skServer);

	if (ret != 0 || strncmp((char*)(decrypted), "AllEars:Web.Login", 17) != 0) {puts("Login failure"); return;}

	// Login successful
	int addrCountNormal, addrCountShield;
	char *addrNormal = loadUserAddressList(upk_hex, "address_normal.aea", &addrCountNormal);
	if (addrNormal == NULL) return;
	char *addrShield = loadUserAddressList(upk_hex, "address_shield.aea", &addrCountShield);
	if (addrShield == NULL) {free(addrNormal); return;}

	size_t lenMbSet;
	unsigned char *mbSet = getUserMessages(post, &lenMbSet);
	if (mbSet == NULL) {free(addrNormal); free(addrShield); return;}

/*
	Login Response Format:
		[1B] Number of Normal Addresses
		[1B] Number of Shield Addresses
		[1B] Number of Message Boxes
		[16B] Normal Address (21c SixBit-Encoded)
		...
		[16B] Shield Address (21c SixBit-Encoded)
		...
		MessageBoxes
*/

	const size_t szBody = 3 + (16 * addrCountNormal) + (16 * addrCountShield) + lenMbSet;
	const size_t szHead = 141 + numDigits(szBody);
	const size_t szResponse = szHead + szBody;

	char data[szResponse + 1];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Content-Length: %zd\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, szBody);

	data[szHead + 0] = (unsigned char)addrCountNormal;
	data[szHead + 1] = (unsigned char)addrCountShield;
	data[szHead + 2] = (unsigned char)1; // MsgCount
	memcpy(data + szHead + 3, addrNormal, addrCountNormal * 16);
	memcpy(data + szHead + 3 + (16 * addrCountNormal), addrShield, addrCountShield * 16);
	memcpy(data + szHead + 3 + (16 * addrCountNormal) + (16 * addrCountShield), mbSet, lenMbSet);

	free(addrNormal);
	free(addrShield);
	free(mbSet);

	sendData(ssl, data, szResponse);
}

// Message sending
static void respond_https_send(mbedtls_ssl_context *ssl, const unsigned char *post, const size_t postLen, const uint32_t clientIp, const unsigned char seed[16]) {
	if (postLen < 33) return;

	char upk_hex[65];
	sodium_bin2hex(upk_hex, 65, post, 32);

	// Get nonce
	char *path = userPath(upk_hex, "nonce");
	if (path == NULL) return;
	int fd = open(path, O_RDONLY);
	if (fd < 0) {free(path); return;}
	if (flock(fd, LOCK_EX) != 0) {close(fd); free(path); return;}

	unsigned char nonce[24];
	ssize_t bytesDone = read(fd, nonce, 24);
	flock(fd, LOCK_UN);
	close(fd);
	free(path);
	if (bytesDone != 24) return;

	memcpy(nonce, &clientIp, 4); // Box will not open if current IP differs from the one that requested the nonce

	int32_t ts;
	memcpy(&ts, nonce + 20, 4);
	const int timeDiff = (int)time(NULL) - ts;
	if (timeDiff < 0 || timeDiff > AEM_NONCE_TIMEDIFF_MAX) return;

	encryptNonce(nonce, seed);

	unsigned char *pkServer = malloc(32); if (pkServer == NULL) return;
	unsigned char *skServer = malloc(32); if (skServer == NULL) return;
	crypto_box_seed_keypair(pkServer, skServer, (unsigned char*)AEM_SERVER_KEY_SEED);
	free(pkServer);

	// Open the Box
	char *decrypted = sodium_malloc(postLen);
	if (decrypted == NULL) {free(skServer); return;}
	const int ret = crypto_box_open_easy((unsigned char*)decrypted, post + 32, postLen - 32, nonce, post, skServer);
	sodium_mprotect_readonly(decrypted);
	free(skServer);
	if (ret != 0) return;

/* Format:
	(From)\n
	(To)\n
	(Title)\n
	(Body)
*/

	const char *endFrom = strchr(decrypted, '\n');
	if (endFrom == NULL) return;
	const char *endTo = strchr(endFrom + 1, '\n');
	if (endTo == NULL) return;

	char *sbFrom = textToSixBit(decrypted, endFrom - decrypted);
	char *sbTo = textToSixBit(endFrom + 1, (endTo) - (endFrom + 1));

	unsigned char pk[32];
	getPublicKeyFromAddress(sbTo, pk, (unsigned char*)"TestTestTestTest");

	unsigned char *headBox = aem_intMsg_makeHeadBox(pk, 0, sbFrom, sbTo);
	free(sbFrom);
	free(sbTo);

	size_t bodyLen = postLen - crypto_box_MACBYTES - 32 - ((endTo + 1) - decrypted);
	unsigned char *bodyBox = aem_intMsg_makeBodyBox(pk, endTo + 1, &bodyLen);

	sodium_free(decrypted);

	const size_t bsLen = 37 + crypto_box_SEALBYTES + bodyLen + crypto_box_SEALBYTES;
	unsigned char *boxSet = malloc(bsLen);
	if (boxSet == NULL) {free(headBox); free(bodyBox); return;}

	memcpy(boxSet, headBox, 37 + crypto_box_SEALBYTES);
	free(headBox);
	memcpy(boxSet + 37 + crypto_box_SEALBYTES, bodyBox, bodyLen + crypto_box_SEALBYTES);
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

static void respond_https_nonce(mbedtls_ssl_context *ssl, const unsigned char *post, const size_t postLen, const uint32_t clientIp, const unsigned char seed[16]) {
	if (postLen != 32) return;

	char upk_hex[65];
	sodium_bin2hex(upk_hex, 65, post, 32);

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

static void handleRequest(mbedtls_ssl_context *ssl, const char *clientHeaders, const size_t chLen, const uint32_t clientIp, const unsigned char seed[16], const struct aem_fileSet *fileSet) {
	char* endHeaders = strstr(clientHeaders, "\r\n\r\n");
	if (endHeaders == NULL) return;
	*(endHeaders + 2) = '\0';

	if (strstr(clientHeaders, "\r\nHost: "AEM_DOMAIN"\r\n") == NULL) return;

	char *end = strpbrk(clientHeaders, "\r\n");
	if (memcmp(end - 9, " HTTP/1.1", 9) != 0) return;
	*(end - 9) = '\0';

	if (memcmp(clientHeaders, "GET /", 5) == 0) {
		const char *url = clientHeaders + 5;
		const size_t urlLen = (end - 9) - url;

		if (urlLen == 0) return respond_https_html(ssl, "index.html", fileSet->htmlFiles, fileSet->htmlCount);
		if (urlLen > 5 && memcmp(url + urlLen - 5, ".html", 5) == 0) return respond_https_html(ssl, url, fileSet->htmlFiles, fileSet->htmlCount);

		if (urlLen == 15 && memcmp(url, ".well-known/dnt", 15) == 0) return respond_https_tsr(ssl);
		if (urlLen == 10 && memcmp(url, "robots.txt",      10) == 0) return respond_https_robots(ssl);

		if (urlLen  >  4 && memcmp(url, "css/", 4) == 0) return respond_https_file(ssl, url + 4, AEM_FILETYPE_CSS, fileSet->cssFiles, fileSet->cssCount);
		if (urlLen  >  4 && memcmp(url, "img/", 4) == 0) return respond_https_file(ssl, url + 4, AEM_FILETYPE_IMG, fileSet->imgFiles, fileSet->imgCount);
		if (urlLen  >  3 && memcmp(url, "js/",  3) == 0) return respond_https_file(ssl, url + 3, AEM_FILETYPE_JS,  fileSet->jsFiles,  fileSet->jsCount);
	} else if (memcmp(clientHeaders, "POST /", 6) == 0) {
		const char *url = clientHeaders + 6;
		const size_t urlLen = (end - 9) - url;

		const char *post = endHeaders + 4;
		const size_t postLen = chLen - (post - clientHeaders);

		if (urlLen == 9 && memcmp(url, "web/nonce", 9) == 0) return respond_https_nonce(ssl, (unsigned char*)post, postLen, clientIp, seed);
		if (urlLen == 9 && memcmp(url, "web/login", 9) == 0) return respond_https_login(ssl, (unsigned char*)post, postLen, clientIp, seed);
		if (urlLen == 8 && memcmp(url, "web/send",  8) == 0) return respond_https_send (ssl, (unsigned char*)post, postLen, clientIp, seed);
	}
}

int respond_https(int sock, mbedtls_x509_crt *srvcert, mbedtls_pk_context *pkey, const uint32_t clientIp, const unsigned char seed[16], const struct aem_fileSet *fileSet) {
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
		handleRequest(&ssl, (char*)req, ret, clientIp, seed, fileSet);
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
