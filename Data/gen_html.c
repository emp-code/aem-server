#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>
#include <zopfli/zopfli.h>

#include "../Common/Brotli.c"
#include "../Global.h"
#include "../utils/GetKey.h"

#include "address.h" // for normal salt
#include "domain.h"

static unsigned char master[crypto_secretbox_KEYBYTES];

static int loadKey(const char * const path, const size_t lenKey, unsigned char * const target) {
	const int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	off_t readBytes = read(fd, nonce, crypto_secretbox_NONCEBYTES);
	if (readBytes != crypto_secretbox_NONCEBYTES) {close(fd); return -1;}

	unsigned char encrypted[lenKey + crypto_secretbox_MACBYTES];
	readBytes = read(fd, encrypted, lenKey + crypto_secretbox_MACBYTES);
	close(fd);
	if (readBytes != (off_t)lenKey + crypto_secretbox_MACBYTES) return -1;

	const int ret = crypto_secretbox_open_easy(target, encrypted, lenKey + crypto_secretbox_MACBYTES, nonce, master);
	return ret;
}

static int html_putKeys(char * const src, const size_t lenSrc) {
	unsigned char key_api[AEM_LEN_KEY_API]; loadKey(AEM_PATH_KEY_API, AEM_LEN_KEY_API, key_api);
	unsigned char key_sig[AEM_LEN_KEY_API]; loadKey(AEM_PATH_KEY_SIG, AEM_LEN_KEY_SIG, key_sig);

	char *placeholder = memmem(src, lenSrc, "All-Ears Mail API PublicKey placeholder, replaced automatically.", 64);
	if (placeholder == NULL) {puts("API-Placeholder not found"); puts(src); return -1;}
	unsigned char api_tmp[crypto_box_SECRETKEYBYTES];
	unsigned char api_pub[crypto_box_PUBLICKEYBYTES];
	char api_hex[65];
	crypto_box_seed_keypair(api_pub, api_tmp, key_api);
	sodium_memzero(key_api, AEM_LEN_KEY_API);
	sodium_memzero(api_tmp, crypto_box_SECRETKEYBYTES);
	sodium_bin2hex(api_hex, 65, api_pub, crypto_box_PUBLICKEYBYTES);
	memcpy(placeholder, api_hex, crypto_box_PUBLICKEYBYTES * 2);

	placeholder = memmem(src, lenSrc, "All-Ears Mail Sig PublicKey placeholder, replaced automatically.", 64);
	if (placeholder == NULL) {puts("Sig-Placeholder not found"); return -1;}
	unsigned char sig_tmp[crypto_sign_SECRETKEYBYTES];
	unsigned char sig_pub[crypto_sign_PUBLICKEYBYTES];
	char sig_hex[65];
	crypto_sign_seed_keypair(sig_pub, sig_tmp, key_sig);
	sodium_memzero(key_api, AEM_LEN_KEY_SIG);
	sodium_memzero(sig_tmp, crypto_sign_SECRETKEYBYTES);
	sodium_bin2hex(sig_hex, 65, sig_pub, crypto_sign_PUBLICKEYBYTES);
	memcpy(placeholder, sig_hex, crypto_sign_PUBLICKEYBYTES * 2);

	placeholder = memmem(src, lenSrc, "AEM Normal Addr Salt placeholder", 32);
	if (placeholder == NULL) {puts("Slt-Placeholder not found"); return -1;}
	char slt_hex[33];
	sodium_bin2hex(slt_hex, 33, AEM_SLT_NRM, AEM_LEN_SLT_NRM);
	memcpy(placeholder, slt_hex, AEM_LEN_SLT_NRM * 2);

	return 0;
}

// Remove email domain placeholder (clearnet)
static int html_remEmail(char * const src, size_t * const lenSrc) {
	char * const placeholder = memmem(src, *lenSrc, "AEM placeholder for email domain", 32);
	if (placeholder == NULL) {puts("Email domain placeholder not found"); return -1;}
	memmove(placeholder, placeholder + 32, (src + *lenSrc) - (placeholder + 32));
	*lenSrc -= 32;

	return 0;
}

// Add email domain (onion service)
static int html_addEmail(char * const src, size_t * const lenSrc) {
	char * const placeholder = memmem(src, *lenSrc, "AEM placeholder for email domain", 32);
	if (placeholder == NULL) {puts("Email domain placeholder not found"); return -1;}
	memcpy(placeholder, AEM_DOMAIN, AEM_DOMAIN_LEN);
	memmove(placeholder + AEM_DOMAIN_LEN, placeholder + 32, (src + *lenSrc) - (placeholder + 32));
	*lenSrc -= (32 - AEM_DOMAIN_LEN);

	return 0;
}

static unsigned char *genHtml(const char * const src_original, const size_t lenSrc_original, size_t * const lenResult, const bool onion) {
	size_t lenSrc = lenSrc_original;
	char * const src = malloc(lenSrc);
	memcpy(src, src_original, lenSrc);

	if (html_putKeys(src, lenSrc) != 0) return NULL;

	if (onion) html_addEmail(src, &lenSrc); else html_remEmail(src, &lenSrc);

	unsigned char *data;
	size_t lenData;

	// Compression
	if (onion) { // Zopfli (deflate)
		ZopfliOptions zopOpt;
		ZopfliInitOptions(&zopOpt);

		lenData = 0;
		data = 0;

		ZopfliCompress(&zopOpt, ZOPFLI_FORMAT_DEFLATE, (unsigned char*)src, lenSrc, &data, &lenData);
		if (data == 0 || lenData < 1) {
			free(src);
			puts("Failed zopfli compression");
			return NULL;
		}
	} else { // Brotli (HTTPS only)
		data = malloc(lenSrc);
		if (data == NULL) {
			free(src);
			puts("Failed allocation");
			return NULL;
		}

		memcpy(data, src, lenSrc);
		lenData = lenSrc;

		if (brotliCompress(&data, &lenData) != 0) {
			free(data);
			free(src);
			puts("Failed brotli compression");
			return NULL;
		}
	}
	free(src);

	unsigned char bodyHash[crypto_hash_sha256_BYTES];
	if (crypto_hash_sha256(bodyHash, (unsigned char*)data, lenData) != 0) {puts("Hash failed"); return NULL;}

	char bodyHashB64[sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(bodyHashB64, sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL), bodyHash, crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL);

	const char * const conn = onion? "://"AEM_ONIONID".onion" : "s://"AEM_DOMAIN;
	const char * const onionLoc = onion? "" : "Onion-Location: http://"AEM_ONIONID".onion\r\n";
	const char * const tlsHeaders = onion? "" : "Expect-CT: enforce, max-age=99999999\r\nStrict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n";

	// Headers
	char headers[2500];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"

		// General headers
		"Cache-Control: public, max-age=999, immutable\r\n" // ~15min
		"Connection: close\r\n"
		"Content-Encoding: %s\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Link: <https://"AEM_DOMAIN">; rel=\"canonical\"\r\n"
		"%s"
		"Server: All-Ears Mail\r\n"
		"Tk: N\r\n"

		// CSP
		"Content-Security-Policy: "
			"connect-src"     " http%s:302/api data:;"
			"frame-src"       " blob:;" // PDF (Chrome)
			"img-src"         " blob: data:;"
			"media-src"       " blob:;"
			"object-src"      " blob:;" // PDF
			"script-src"      " https://cdn.jsdelivr.net/gh/emp-code/ https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdn.jsdelivr.net/gh/jedisct1/libsodium.js@0.7.9/dist/browsers/sodium.js 'unsafe-eval';"
			"style-src"       " https://cdn.jsdelivr.net/gh/emp-code/ 'unsafe-inline';" // Inline: For displaying PDF/HTML files

			"base-uri"        " 'none';"
			"child-src"       " 'none';"
			"default-src"     " 'none';"
			"font-src"        " 'none';"
			"form-action"     " 'none';"
			"frame-ancestors" " 'none';"
			"manifest-src"    " 'none';"
			"prefetch-src"    " 'none';"
			"worker-src"      " 'none';"

			"block-all-mixed-content;"
			"plugin-types application/pdf;"
			"require-sri-for script style;"
		"\r\n"

		// PP
		"Permissions-Policy: "
			"clipboard-write"                 "=(self),"
			"focus-without-user-activation"   "=(self),"
			"fullscreen"                      "=(self),"

			"accelerometer"                   "=(),"
			"ambient-light-sensor"            "=(),"
			"autoplay"                        "=(),"
			"battery"                         "=(),"
			"camera"                          "=(),"
			"ch-device-memory"                "=(),"
			"ch-downlink"                     "=(),"
			"ch-dpr"                          "=(),"
			"ch-ect"                          "=(),"
			"ch-rtt"                          "=(),"
			"ch-save-data"                    "=(),"
			"ch-ua"                           "=(),"
			"ch-ua-arch"                      "=(),"
			"ch-ua-mobile"                    "=(),"
			"ch-ua-model"                     "=(),"
			"ch-ua-platform"                  "=(),"
			"ch-viewport-height"              "=(),"
			"ch-viewport-width"               "=(),"
			"ch-width"                        "=(),"
			"clipboard-read"                  "=(),"
			"cross-origin-isolated"           "=(),"
			"display-capture"                 "=(),"
			"document-domain"                 "=(),"
			"encrypted-media"                 "=(),"
			"execution-while-not-rendered"    "=(),"
			"execution-while-out-of-viewport" "=(),"
			"gamepad"                         "=(),"
			"geolocation"                     "=(),"
			"gyroscope"                       "=(),"
			"idle-detection"                  "=(),"
			"magnetometer"                    "=(),"
			"microphone"                      "=(),"
			"midi"                            "=(),"
			"navigation-override"             "=(),"
			"payment"                         "=(),"
			"picture-in-picture"              "=(),"
			"publickey-credentials-get"       "=(),"
			"screen-wake-lock"                "=(),"
			"speaker-selection"               "=(),"
			"sync-xhr"                        "=(),"
			"usb"                             "=(),"
			"web-share"                       "=(),"
			"xr-spatial-tracking"             "=()"
		"\r\n"

		// Misc security headers
		"%s"
		"Cross-Origin-Embedder-Policy: require-corp\r\n"
		"Cross-Origin-Opener-Policy: same-origin\r\n"
		"Cross-Origin-Resource-Policy: same-origin\r\n"
		"Digest: sha-256=%s\r\n"
		"Referrer-Policy: no-referrer\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-DNS-Prefetch-Control: off\r\n"
		"X-Frame-Options: deny\r\n"
		"X-XSS-Protection: 1; mode=block\r\n"
		"\r\n"
	, onion? "deflate" : "br", // Content-Encoding
	lenData, // Content-Length
	onionLoc,
	conn, // CSP connect
	tlsHeaders,
	bodyHashB64); // Digest

	const size_t lenHeaders = strlen(headers);

	*lenResult = lenHeaders + lenData;
	unsigned char *result = malloc(*lenResult);
	memcpy(result, headers, lenHeaders);
	memcpy(result + lenHeaders, data, lenData);
	free(data);

	return result;
}

static void printBin(const char * const def, const unsigned char * const buf, const size_t len) {
	printf("#define %s (const unsigned char[]) {", def);

	for (size_t i = 0; i < len; i++) {
		printf("'\\x%.2x'", buf[i]);
		if (i < (len - 1)) printf(",");
	}

	puts("}\n");
}

static void printSts(void) {
	char tmp[512];
	sprintf(tmp,
		"HTTP/1.1 200 aem\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Connection: close\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Tk: N\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-Robots-Tag: noindex\r\n"
		"\r\n"
		"version: STSv1\n"
		"mode: enforce\n"
		"mx: "AEM_DOMAIN"\n"
		"max_age: 31557600"
	, 51 + AEM_DOMAIN_LEN);

	const size_t len = strlen(tmp);

	printf("#define AEM_MTASTS_SIZE %zu\n", len);
	printf("#define AEM_MTASTS_DATA (const unsigned char[]) {");

	for (size_t i = 0; i < len; i++) {
		printf("'\\x%.2x'", tmp[i]);
		if (i < len - 1) printf(",");
	}

	puts("}\n");
}

int main(int argc, char *argv[]) {
	if (argc != 2) {printf("Usage: %s input.html\n", argv[0]); return EXIT_FAILURE;}
	if (sodium_init() < 0) {puts("Terminating: Failed sodium_init()"); return EXIT_FAILURE;}
	if (getKey(master) != 0) {puts("Terminating: Failed reading key"); return EXIT_FAILURE;}

	puts("#ifndef AEM_DATA_HTML_H");
	puts("#define AEM_DATA_HTML_H");
	puts("");

	printSts();

	const int fd = open(argv[1], O_RDONLY);
	if (fd < 0) return EXIT_FAILURE;
	const off_t lenHtml = lseek(fd, 0, SEEK_END);
	if (lenHtml < 1) return EXIT_FAILURE;
	char html[lenHtml];
	const ssize_t rd = pread(fd, html, lenHtml, 0);
	close(fd);
	if (rd != lenHtml) return EXIT_FAILURE;

	size_t html_clr_size;
	unsigned char * const html_clr_data = genHtml(html, lenHtml, &html_clr_size, false);
	if (html_clr_data == NULL) {sodium_memzero(master, crypto_secretbox_KEYBYTES); return EXIT_FAILURE;}
	printf("#define AEM_HTML_CLR_SIZE %zu\n", html_clr_size);
	printBin("AEM_HTML_CLR_DATA", html_clr_data, html_clr_size);
	free(html_clr_data);

	size_t html_oni_size;
	unsigned char * const html_oni_data = genHtml(html, lenHtml, &html_oni_size, true);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	if (html_oni_data == NULL) return EXIT_FAILURE;
	printf("#define AEM_HTML_ONI_SIZE %zu\n", html_oni_size);
	printBin("AEM_HTML_ONI_DATA", html_oni_data, html_oni_size);
	free(html_oni_data);

	puts("#endif");

	return EXIT_SUCCESS;
}
