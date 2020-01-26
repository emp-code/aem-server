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

static char *responseCss = NULL;
static char *responseHtm = NULL;
static char *responseJsa = NULL;
static char *responseJsm = NULL;

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

__attribute__((warn_unused_result))
int setResponse(const int type, const unsigned char * const fileData, const size_t fileSize) {
	if (lenDomain < 1) return -1;

	if (
		(type == AEM_FILETYPE_CSS && responseCss != NULL)
	|| (type == AEM_FILETYPE_HTM && responseHtm != NULL)
	|| (type == AEM_FILETYPE_JSA && responseJsa != NULL)
	|| (type == AEM_FILETYPE_JSM && responseJsm != NULL)
	) return -1;

	size_t lenHeaders = (type == AEM_FILETYPE_HTM) ? 1419 + lenDomain * 4 : 350;

	if (fileSize > 99999) return -1;
	else if (fileSize > 9999) lenHeaders += 5;
	else if (fileSize > 999)  lenHeaders += 4;
	else if (fileSize > 99)   lenHeaders += 3;
	else if (fileSize > 9)    lenHeaders += 2;
	else lenHeaders++;

	char *ct = NULL;
	size_t lenCt = 0;
	switch(type) {
		case AEM_FILETYPE_CSS:  ct = "text/css; charset=utf-8";  lenCt = 23; break;
		case AEM_FILETYPE_JSA:
		case AEM_FILETYPE_JSM: ct = "application/javascript; charset=utf-8"; lenCt = 37;
	}
	lenHeaders += lenCt;

	char *response = sodium_malloc(lenHeaders + fileSize);
	if (response == NULL) return -1;

	if (type == AEM_FILETYPE_CSS || type == AEM_FILETYPE_JSA || type == AEM_FILETYPE_JSM) {
		sprintf(response,
			"HTTP/1.1 200 aem\r\n"
			"Tk: N\r\n"
			"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
			"Expect-CT: enforce; max-age=99999999\r\n"
			"Connection: close\r\n"
			"Cache-Control: public, max-age=999, immutable\r\n" // ~15min
			"Content-Encoding: br\r\n"
			"Content-Type: %.*s\r\n"
			"Content-Length: %zd\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"X-Robots-Tag: noindex\r\n"
			"Cross-Origin-Resource-Policy: same-origin\r\n"
			"\r\n"
		, (int)lenCt, ct, fileSize);
	} else if (type == AEM_FILETYPE_HTM) {
		sprintf(response,
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
				"connect-src"     " https://%.*s:302/api/;"
				"script-src"      " https://%.*s/files/main.js https://%.*s/files/all-ears.js https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdnjs.cloudflare.com/ajax/libs/js-nacl/1.3.2/nacl_factory.min.js;"
				"style-src"       " https://%.*s/files/main.css;"

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
		, fileSize, (int)lenDomain, domain, (int)lenDomain, domain, (int)lenDomain, domain, (int)lenDomain, domain);
	}

	memcpy(response + lenHeaders, fileData, fileSize);
	sodium_mprotect_readonly(response);

	switch(type) {
		case AEM_FILETYPE_CSS: responseCss = response; lenResponseCss = lenHeaders + fileSize; break;
		case AEM_FILETYPE_HTM: responseHtm = response; lenResponseHtm = lenHeaders + fileSize; break;
		case AEM_FILETYPE_JSA: responseJsa = response; lenResponseJsa = lenHeaders + fileSize; break;
		case AEM_FILETYPE_JSM: responseJsm = response; lenResponseJsm = lenHeaders + fileSize; break;
	}

	return 0;
}

void https_respond(mbedtls_ssl_context * const ssl, const char * const url, const size_t len) {
	if (len == 0 || url == NULL) return sendData(ssl, responseHtm, lenResponseHtm);

	if (len == 14 && memcmp(url, "files/main.css",    len) == 0) return sendData(ssl, responseCss,  lenResponseCss);
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
