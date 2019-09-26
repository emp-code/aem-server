#include <string.h>
#include <stdio.h>

#include <mbedtls/ssl.h>

#include "aem_file.h"
#include "https_common.h"

#include "https_get.h"

#define AEM_FILETYPE_CSS 1
#define AEM_FILETYPE_IMG 2
#define AEM_FILETYPE_JS  3

// Javascript, CSS, images etc
static void respond_https_file(mbedtls_ssl_context * const ssl, const char * const name, const size_t lenName, const int fileType, const struct aem_file * const files, const int fileCount) {
	int reqNum = -1;

	for (int i = 0; i < fileCount; i++) {
		if (strlen(files[i].filename) == lenName && memcmp(files[i].filename, name, lenName) == 0) {
			reqNum = i;
			break;
		}
	}

	if (reqNum < 0) return;

	if (files[reqNum].lenData > 999999) return;

	const char *mediatype;
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

	char data[287 + mtLen + files[reqNum].lenData];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"%s"
		"Content-Type: %.*s\r\n"
		"Content-Length: %zd\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"Cross-Origin-Resource-Policy: same-origin\r\n"
		"\r\n"
	, (fileType == AEM_FILETYPE_CSS || fileType == AEM_FILETYPE_JS) ? "Content-Encoding: br\r\n" : "", mtLen, mediatype, files[reqNum].lenData);

	const size_t lenHeaders = strlen(data);
	memcpy(data + lenHeaders, files[reqNum].data, files[reqNum].lenData);

	sendData(ssl, data, lenHeaders + files[reqNum].lenData);
}

static void respond_https_html(mbedtls_ssl_context * const ssl, const char * const name, const size_t lenName, const struct aem_file * const files, const int fileCount, const char * const domain, const size_t lenDomain) {
	int reqNum = -1;

	for (int i = 0; i < fileCount; i++) {
		if (strlen(files[i].filename) == lenName && memcmp(files[i].filename, name, lenName) == 0) {
			reqNum = i;
			break;
		}
	}

	if (reqNum < 0) return;

	if (files[reqNum].lenData > 99999) return;

	char data[1300 + (lenDomain * 4) + files[reqNum].lenData];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"Content-Encoding: br\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Content-Length: %zd\r\n"

		"Content-Security-Policy: "
			"connect-src"     " https://%.*s/api/;"
			"img-src"         " https://%.*s/img/;"
			"script-src"      " https://%.*s/js/ https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdnjs.cloudflare.com/ajax/libs/js-nacl/1.3.2/nacl_factory.min.js;"
			"style-src"       " https://%.*s/css/;"

			"base-uri"        " 'none';"
			"child-src"       " 'none';"
			"default-src"     " 'none';"
			"font-src"        " 'none';"
			"form-action"     " 'none';"
			"frame-ancestors" " 'none';"
			"frame-src"       " 'none';"
			"manifest-src"    " 'none';"
			"media-src"       " 'none';"
			"object-src"      " 'none';"
			"prefetch-src"    " 'none';"
			"worker-src"      " 'none';"

			"block-all-mixed-content;"
			"sandbox allow-scripts allow-same-origin;"
		"\r\n"

		"Feature-Policy: "
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
		"X-Frame-Options: deny\r\n"
		"X-XSS-Protection: 1; mode=block\r\n"
		"\r\n"
	, files[reqNum].lenData, (int)lenDomain, domain, (int)lenDomain, domain, (int)lenDomain, domain, (int)lenDomain, domain);

	size_t lenHeaders = strlen(data);
	memcpy(data + lenHeaders, files[reqNum].data, files[reqNum].lenData);

	sendData(ssl, data, lenHeaders + files[reqNum].lenData);
}

void https_get(mbedtls_ssl_context * const ssl, const char * const url, const size_t lenUrl, const struct aem_fileSet * const fileSet, const char * const domain, const size_t lenDomain) {
	if (lenUrl == 0) return respond_https_html(ssl, "index.html", 10, fileSet->htmlFiles, fileSet->htmlCount, domain, lenDomain);
	if (lenUrl > 5 && memcmp(url + lenUrl - 5, ".html", 5) == 0) return respond_https_html(ssl, url, lenUrl, fileSet->htmlFiles, fileSet->htmlCount, domain, lenDomain);

	if (lenUrl > 8 && memcmp(url, "css/", 4) == 0) return respond_https_file(ssl, url + 4, lenUrl - 4, AEM_FILETYPE_CSS, fileSet->cssFiles, fileSet->cssCount);
	if (lenUrl > 8 && memcmp(url, "img/", 4) == 0) return respond_https_file(ssl, url + 4, lenUrl - 4, AEM_FILETYPE_IMG, fileSet->imgFiles, fileSet->imgCount);
	if (lenUrl > 6 && memcmp(url, "js/",  3) == 0) return respond_https_file(ssl, url + 3, lenUrl - 3, AEM_FILETYPE_JS,  fileSet->jsFiles,  fileSet->jsCount);
}
