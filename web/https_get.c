#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <sodium.h>

#include "../Global.h"

#include "https_get.h"

#include "Include/https_common.h"
#include "global.h"

static unsigned char *responseCss = NULL;
static unsigned char *responseHtm = NULL;
static unsigned char *responseJsa = NULL;
static unsigned char *responseJsm = NULL;

static size_t lenResponseCss = 0;
static size_t lenResponseHtm = 0;
static size_t lenResponseJsm = 0;
static size_t lenResponseJsa = 0;

void freeFiles(void) {
	if (responseCss != NULL) sodium_free(responseCss);
	if (responseHtm != NULL) sodium_free(responseHtm);
	if (responseJsa != NULL) sodium_free(responseJsa);
	if (responseJsm != NULL) sodium_free(responseJsm);

	lenResponseCss = 0;
	lenResponseHtm = 0;
	lenResponseJsa = 0;
	lenResponseJsm = 0;
}

void setResponse(const int type, unsigned char * const data, const size_t len) {
	switch (type) {
		case AEM_FILETYPE_CSS: responseCss = data; lenResponseCss = len; break;
		case AEM_FILETYPE_HTM: responseHtm = data; lenResponseHtm = len; break;
		case AEM_FILETYPE_JSA: responseJsa = data; lenResponseJsa = len; break;
		case AEM_FILETYPE_JSM: responseJsm = data; lenResponseJsm = len; break;
	}
}

void https_respond(mbedtls_ssl_context * const ssl, const char * const url, const size_t len) {
	if (len == 0 || url == NULL) return sendData(ssl, responseHtm, lenResponseHtm);

	if (len == 14 && memcmp(url, "files/main.css",    len) == 0) return sendData(ssl, responseCss, lenResponseCss);
	if (len == 17 && memcmp(url, "files/all-ears.js", len) == 0) return sendData(ssl, responseJsa, lenResponseJsa);
	if (len == 13 && memcmp(url, "files/main.js",     len) == 0) return sendData(ssl, responseJsm, lenResponseJsm);
}

void https_mtasts(mbedtls_ssl_context * const ssl) {
	char data[317 + lenDomain];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-Robots-Tag: noindex\r\n"
		"\r\n"
		"version: STSv1\n"
		"mode: enforce\n"
		"mx: %.*s\n"
		"max_age: 31557600"
	, 51 + lenDomain, (int)lenDomain, domain);

	sendData(ssl, data, 316 + lenDomain);
}

void https_robots(mbedtls_ssl_context * const ssl) {
	sendData(ssl,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: 55\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-Robots-Tag: noindex\r\n"
		"\r\n"
		"User-agent: *\n"
		"Disallow: /.well-known/\n"
		"Disallow: /files/"
	, 371);
}

// Tracking Status Resource for DNT
void https_tsr(mbedtls_ssl_context * const ssl) {
	sendData(ssl,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Content-Type: application/tracking-status+json\r\n"
		"Content-Length: 17\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"\r\n"
		"{\"tracking\": \"N\"}"
	, 317);
}
