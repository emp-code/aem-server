#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <sodium.h>

#include "https_get.h"

#include "Include/Brotli.h"
#include "Include/https_common.h"
#include "global.h"

#define AEM_PATH_CSS  "main.css"
#define AEM_PATH_HTML "index.html"
#define AEM_PATH_JSAE "all-ears.js"
#define AEM_PATH_JSMN "main.js"

static size_t lenResponseCss  = 0;
static size_t lenResponseHtml = 0;
static size_t lenResponseJsMn = 0;
static size_t lenResponseJsAe = 0;

static char *responseCss = NULL;
static char *responseHtml = NULL;
static char *responseJsAe = NULL;
static char *responseJsMn = NULL;

void freeFiles(void) {
	if (responseCss  != NULL) {sodium_free(responseCss);  responseCss  = NULL;}
	if (responseHtml != NULL) {sodium_free(responseHtml); responseHtml = NULL;}
	if (responseJsAe != NULL) {sodium_free(responseJsAe); responseJsAe = NULL;}
	if (responseJsMn != NULL) {sodium_free(responseJsMn); responseJsMn = NULL;}

	lenResponseCss  = 0;
	lenResponseHtml = 0;
	lenResponseJsAe = 0;
	lenResponseJsMn = 0;
}

__attribute__((warn_unused_result))
int loadFile(const int type) {
	int fd;
	if      (type == AEM_FILETYPE_CSS)  {fd = open(AEM_PATH_CSS,  O_RDONLY);}
	else if (type == AEM_FILETYPE_HTML) {fd = open(AEM_PATH_HTML, O_RDONLY);}
	else if (type == AEM_FILETYPE_JSAE) {fd = open(AEM_PATH_JSAE, O_RDONLY);}
	else if (type == AEM_FILETYPE_JSMN) {fd = open(AEM_PATH_JSMN, O_RDONLY);}
	else return -1;

	// TODO for reloading: Free response if not null

	off_t fileBytes = lseek(fd, 0, SEEK_END);
	if (fileBytes < 0) {close(fd); return -1;}

	char *fileData = malloc(fileBytes);

	int ret = pread(fd, fileData, fileBytes, 0);
	close(fd);
	if (ret != fileBytes) {
		free(fileData);
		return -1;
	}

	size_t compressedBytes = fileBytes;
	ret = brotliCompress(&fileData, (size_t*)&compressedBytes);
	if (ret != 0) {
		free(fileData);
		return -1;
	}

	size_t lenHeaders = (type == AEM_FILETYPE_HTML) ? 1420 + lenDomain * 4 : 350;

	if (compressedBytes > 99999) {free(fileData); return -1;}
	else if (compressedBytes > 9999) lenHeaders += 5;
	else if (compressedBytes > 999)  lenHeaders += 4;
	else if (compressedBytes > 99)   lenHeaders += 3;
	else if (compressedBytes > 9)    lenHeaders += 2;
	else lenHeaders++;

	char *ct = NULL;
	size_t lenCt = 0;
	switch(type) {
		case AEM_FILETYPE_CSS:  ct = "text/css; charset=utf-8";  lenCt = 23; break;
		case AEM_FILETYPE_JSAE:
		case AEM_FILETYPE_JSMN: ct = "application/javascript; charset=utf-8"; lenCt = 37;
	}
	lenHeaders += lenCt;

	char *response = sodium_malloc(lenHeaders + compressedBytes);

	if (type == AEM_FILETYPE_CSS || type == AEM_FILETYPE_JSAE || type == AEM_FILETYPE_JSMN) {
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
		, (int)lenCt, ct, compressedBytes);
	} else if (type == AEM_FILETYPE_HTML) {
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
				"connect-src"     " https://%.*s:7850/api/;"
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
		, compressedBytes, (int)lenDomain, domain, (int)lenDomain, domain, (int)lenDomain, domain, (int)lenDomain, domain);
	}

	memcpy(response + lenHeaders, fileData, compressedBytes);
	free(fileData);

	sodium_mprotect_readonly(response);

	switch(type) {
		case AEM_FILETYPE_CSS:  responseCss  = response; lenResponseCss  = lenHeaders + compressedBytes; break;
		case AEM_FILETYPE_HTML: responseHtml = response; lenResponseHtml = lenHeaders + compressedBytes; break;
		case AEM_FILETYPE_JSAE: responseJsAe = response; lenResponseJsAe = lenHeaders + compressedBytes; break;
		case AEM_FILETYPE_JSMN: responseJsMn = response; lenResponseJsMn = lenHeaders + compressedBytes; break;
	}

	return 0;
}

void https_respond(mbedtls_ssl_context * const ssl, const char * const url, const size_t len) {
	if (len == 0) return sendData(ssl, responseHtml, lenResponseHtml);

	if (len == 14 && memcmp(url, "files/main.css",    len) == 0) return sendData(ssl, responseCss,  lenResponseCss);
	if (len == 17 && memcmp(url, "files/all-ears.js", len) == 0) return sendData(ssl, responseJsAe, lenResponseJsAe);
	if (len == 13 && memcmp(url, "files/main.js",     len) == 0) return sendData(ssl, responseJsMn, lenResponseJsMn);
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
		"Disallow: /files/\n"
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
