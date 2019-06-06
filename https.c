#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/xtea.h"

#include "crypto_box.h"

#include "Includes/Base64.h"

#include "https.h"

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
	lseek(fd, 0, SEEK_SET);

	char headers[92];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"
		"TSV: N\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"
		"\r\n"
	, lenHtml);

	const size_t lenHeaders = strlen(headers);

	char data[lenHeaders + lenHtml];
	const int bytesRead = read(fd, data + lenHeaders, lenHtml);
	close(fd);
	if (bytesRead != lenHtml) return;

	memcpy(data, headers, lenHeaders);

	sendData(ssl, data, lenHeaders + lenHtml);
}

// Javascript
static void respond_https_js(mbedtls_ssl_context *ssl, const char *jsPath, const size_t jsLen) {
	char path[jsLen + 1];
	memcpy(path, jsPath, jsLen);
	path[jsLen] = 0x00;

	int fd = open(path, O_RDONLY);
	if (fd < 0) return;

	const size_t lenJs = lseek(fd, 0, SEEK_END);
	if (lenJs < 10 || lenJs > 99999) {close(fd); return;}
	lseek(fd, 0, SEEK_SET);

	char headers[100];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"
		"TSV: N\r\n"
		"Content-Type: application/javascript; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"
		"\r\n"
	, lenJs);

	const size_t lenHeaders = strlen(headers);

	char data[lenHeaders + lenJs];
	const int bytesRead = read(fd, data + lenHeaders, lenJs);
	close(fd);
	if (bytesRead != lenJs) return;

	memcpy(data, headers, lenHeaders);

	sendData(ssl, data, lenHeaders + lenJs);
}

// Tracking Status Resource for DNT
static void respond_https_tsr(mbedtls_ssl_context *ssl) {
	const char* data =
	"HTTP/1.1 200 aem\r\n"
	"TSV: N\r\n"
	"Content-Type: application/tracking-status+json\r\n"
	"Content-Length: 16\r\n"
	"\r\n"
	"{\"tracking\":\"N\"}";

	sendData(ssl, data, 112);
}

// robots.txt
static void respond_https_robots(mbedtls_ssl_context *ssl) {
	const char* data =
	"HTTP/1.1 200 aem\r\n"
	"TSV: N\r\n"
	"Content-Type: text/plain; charset=utf-8\r\n"
	"Content-Length: 26\r\n"
	"\r\n"
	"User-agent: *\r\n"
	"Disallow: /";

	sendData(ssl, data, 115);
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
	unsigned char nonce[24];

	char path[60];
	noncePath(path, b64_upk);

	int fd = open(path, O_RDONLY);
	ssize_t bytesDone = read(fd, nonce, 24);
	close(fd);
	if (bytesDone != 24) return;

	memcpy(nonce, &clientIp, 4); // Box will not open if current IP differs from the one that requested the none

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
	"TSV: N\r\n"
	"Content-Type: text/plain; charset=utf-8\r\n"
	"Content-Length: 4\r\n"
	"\r\n"
	"TODO";

	sendData(ssl, data, strlen(data));
}

// Request for a nonce to be used with a NaCl Box. URL format: name.tld/web/nonce/public-key-in-base64
static void respond_https_nonce(mbedtls_ssl_context *ssl, const char *b64_upk, const uint32_t clientIp, const unsigned char seed[16]) {
	unsigned char nonce[24];

	int fd = open("/dev/urandom", O_RDONLY);
	unsigned char nonce_random[16];
	ssize_t bytesDone = read(fd, nonce_random, 16);
	close(fd);
	if (bytesDone != 16) return;

	const uint32_t ts = (uint32_t)time(NULL);
	memcpy(nonce, &clientIp, 4); // Client IP. Protection against third parties intercepting the Box.
	memcpy(nonce + 4, random, 16);
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
	if (b64_nonceLen < 10 || b64_nonceLen > 99) return;

	char data[89 + b64_nonceLen];

	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"TSV: N\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"
		"\r\n%.*s"
	, b64_nonceLen, (int)b64_nonceLen, b64_nonce);

	sendData(ssl, data, 89 + b64_nonceLen);
}

static void handleRequest(mbedtls_ssl_context *ssl, const char *clientHeaders, const size_t chLen, const uint32_t clientIp, const unsigned char seed[16]) {
	if (chLen < 14 || memcmp(clientHeaders, "GET /", 5) != 0) return;

	char* end = strpbrk(clientHeaders + 5, "\r\n");
	if (end == NULL) return;

	if (memcmp(end - 9, " HTTP/1.1", 9) != 0) return;

	const size_t urlLen = end - clientHeaders - 14; // 5 + 9

	if (urlLen == 0) return respond_https_home(ssl); // GET / HTTP/1.1
	if (urlLen == 15 && memcmp(clientHeaders + 5, ".well-known/dnt", 15) == 0) return respond_https_tsr(ssl);
	if (urlLen == 10 && memcmp(clientHeaders + 5, "robots.txt",      10) == 0) return respond_https_robots(ssl);
	if (urlLen > 3 && memcmp(clientHeaders + 5, "js/", 3) == 0) return respond_https_js(ssl, clientHeaders + 5, urlLen);
	if (urlLen > 10 && memcmp(clientHeaders + 5, "web/login/", 10) == 0) return respond_https_login(ssl, clientHeaders + 5, urlLen, clientIp, seed);
	if (urlLen == 54 && memcmp(clientHeaders + 5, "web/nonce/", 10) == 0) return respond_https_nonce(ssl, clientHeaders + 15, clientIp, seed);
}

void respond_https(int sock, const unsigned char *httpsCert, const size_t lenHttpsCert, const unsigned char *httpsKey, const size_t lenHttpsKey, const uint32_t clientIp, const unsigned char seed[16]) {
	// Load the certificates and private RSA key
	mbedtls_x509_crt srvcert;
	mbedtls_x509_crt_init(&srvcert);
	int ret = mbedtls_x509_crt_parse(&srvcert, httpsCert, lenHttpsCert);

	if (ret != 0) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		printf("ERROR: Loading server cert failed - mbedtls_x509_crt_parse returned %d: %s\n", ret, error_buf);
		return;
	}

	mbedtls_pk_context pkey;
	mbedtls_pk_init(&pkey);
	ret = mbedtls_pk_parse_key(&pkey, httpsKey, lenHttpsKey + 1, NULL, 0);
	if (ret != 0) {
		printf("ERROR: mbedtls_pk_parse_key returned %x\n", ret);
		return;
	}

	// Seed the RNG
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16)) != 0) {
		printf("ERROR: mbedtls_ctr_drbg_seed returned %d\n", ret);
		return;
	}

	// Setting up the SSL
	mbedtls_ssl_config conf;
	mbedtls_ssl_config_init(&conf);

	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		printf("Failed; mbedtls_ssl_config_defaults returned %d\n\n", ret);
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
		printf("ERROR: mbedtls_ssl_conf_own_cert returned %d\n", ret);
		return;
	}

	mbedtls_ssl_context ssl;
	mbedtls_ssl_init(&ssl);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		printf("ERROR: mbedtls_ssl_setup returned %d\n", ret);
		return;
	}

	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	// Handshake
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			/*if (ret == -80) {
				mbedtls_ssl_session_reset(&ssl);
				continue;
			}*/

			char error_buf[100];
			mbedtls_strerror(ret, error_buf, 100);
			printf("ERROR: mbedtls_ssl_handshake returned %d: %s\n", ret, error_buf);
			mbedtls_ssl_session_reset(&ssl);
			mbedtls_ssl_free(&ssl);
			return;
		}
	}

	unsigned char req[AEM_HTTPS_BUFLEN + 1];
	bzero(req, AEM_HTTPS_BUFLEN);

	do {
		ret = mbedtls_ssl_read(&ssl, req, AEM_HTTPS_BUFLEN);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret > 0) {
		handleRequest(&ssl, (char*)req, ret, clientIp, seed);
	} else if (ret != 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY && ret != MBEDTLS_ERR_SSL_CONN_EOF && ret != MBEDTLS_ERR_NET_CONN_RESET) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		printf( "ERROR: Incoming connection failed: %d: %s\n", ret, error_buf);
	}

	mbedtls_ssl_session_reset(&ssl);
	mbedtls_ssl_free(&ssl);
	mbedtls_x509_crt_free(&srvcert);
	mbedtls_pk_free(&pkey);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}
