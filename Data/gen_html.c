#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>
#include <zopfli/zopfli.h>

#include "../Global.h"
#include "../Common/Brotli.h"
#include "../Common/GetKey.h"
#include "../Common/PrintDef.c"

#include "address.h" // for normal salt
#include "domain.h"

static int html_putKeys(char * const src, const size_t lenSrc) {
	unsigned char master[crypto_kdf_KEYBYTES];
	if (getKey(master) != 0) return -1;

	unsigned char baseKey[crypto_kdf_KEYBYTES];

	// API PK
	crypto_kdf_derive_from_key(baseKey, crypto_kdf_KEYBYTES, 1, "AEM_Api0", master);

	unsigned char box_seed[crypto_box_SEEDBYTES];
	unsigned char box_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char box_sk[crypto_box_SECRETKEYBYTES];
	crypto_kdf_derive_from_key(box_seed, crypto_box_SEEDBYTES, 1, "AEM_API1", baseKey);
	crypto_box_seed_keypair(box_pk, box_sk, box_seed);
	sodium_memzero(box_sk, crypto_box_SECRETKEYBYTES);
	sodium_memzero(box_seed, crypto_box_SEEDBYTES);

	char *placeholder = memmem(src, lenSrc, "All-Ears Mail API BoxPubKey placeholder, replaced automatically.", 64);
	if (placeholder == NULL) {fputs("API-Box placeholder not found", stderr); return -1;}
	sodium_bin2hex(placeholder, 999, box_pk, crypto_box_PUBLICKEYBYTES);
	placeholder[crypto_box_PUBLICKEYBYTES * 2] = '"';

	// API Sig PK
	unsigned char sig_seed[crypto_sign_SEEDBYTES];
	unsigned char sig_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sig_sk[crypto_sign_SECRETKEYBYTES];

	crypto_kdf_derive_from_key(sig_seed, crypto_box_SEEDBYTES, 1, "AEM_Sig1", baseKey);
	crypto_sign_seed_keypair(sig_pk, sig_sk, sig_seed);
	sodium_memzero(sig_seed, crypto_sign_SEEDBYTES);
	sodium_memzero(sig_sk, crypto_sign_SECRETKEYBYTES);

	placeholder = memmem(src, lenSrc, "All-Ears Mail API SigPubKey placeholder, replaced automatically.", 64);
	if (placeholder == NULL) {fputs("API-Sig placeholder not found", stderr); return -1;}
	sodium_bin2hex(placeholder, 999, sig_pk, crypto_sign_PUBLICKEYBYTES);
	placeholder[crypto_sign_PUBLICKEYBYTES * 2] = '"';

	// Dlv Sig PK
	crypto_kdf_derive_from_key(baseKey, crypto_kdf_KEYBYTES, 1, "AEM_Dlv0", master);

	crypto_kdf_derive_from_key(sig_seed, crypto_sign_SEEDBYTES, 1, "AEM_Dlv1", baseKey);
	crypto_sign_seed_keypair(sig_pk, sig_sk, sig_seed);
	sodium_memzero(sig_sk, crypto_sign_SECRETKEYBYTES);
	sodium_memzero(sig_seed, crypto_sign_SEEDBYTES);

	placeholder = memmem(src, lenSrc, "All-Ears Mail Dlv SigPubKey placeholder, replaced automatically.", 64);
	if (placeholder == NULL) {fputs("Dlv-Sig placeholder not found", stderr); return -1;}
	sodium_bin2hex(placeholder, 999, sig_pk, crypto_sign_PUBLICKEYBYTES);
	placeholder[crypto_sign_PUBLICKEYBYTES * 2] = '"';

	// Normal Salt
	placeholder = memmem(src, lenSrc, "AEM Normal Addr Salt placeholder", 32);
	if (placeholder == NULL) {fputs("Salt placeholder not found", stderr); return -1;}
	sodium_bin2hex(placeholder, 999, AEM_SLT_NRM, AEM_LEN_SLT_NRM);
	placeholder[AEM_LEN_SLT_NRM * 2] = '"';

	return 0;
}

// Remove email domain placeholder (clearnet)
static int html_remEmail(char * const src, size_t * const lenSrc) {
	char * const placeholder = memmem(src, *lenSrc, "AEM placeholder for email domain", 32);
	if (placeholder == NULL) {fputs("Email domain placeholder not found", stderr); return -1;}
	memmove(placeholder, placeholder + 32, (src + *lenSrc) - (placeholder + 32));
	*lenSrc -= 32;

	return 0;
}

// Add email domain (onion service)
static int html_addEmail(char * const src, size_t * const lenSrc) {
	char * const placeholder = memmem(src, *lenSrc, "AEM placeholder for email domain", 32);
	if (placeholder == NULL) {fputs("Email domain placeholder not found", stderr); return -1;}
	memcpy(placeholder, AEM_DOMAIN, AEM_DOMAIN_LEN);
	memmove(placeholder + AEM_DOMAIN_LEN, placeholder + 32, (src + *lenSrc) - (placeholder + 32));
	*lenSrc -= (32 - AEM_DOMAIN_LEN);

	return 0;
}

static unsigned char *genHtml(const char * const src_original, const size_t lenSrc_original, size_t * const lenResult, const bool onion) {
	size_t lenSrc = lenSrc_original;
	char * const src = malloc(lenSrc);
	if (src == NULL) return NULL;
	memcpy(src, src_original, lenSrc);

	if (html_putKeys(src, lenSrc) != 0) {free(src); return NULL;}

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
			fputs("Failed zopfli compression", stderr);
			return NULL;
		}
	} else { // Brotli (HTTPS only)
		data = malloc(lenSrc);
		if (data == NULL) {
			free(src);
			fputs("Failed allocation", stderr);
			return NULL;
		}

		memcpy(data, src, lenSrc);
		lenData = lenSrc;

		if (brotliCompress(&data, &lenData) != 0) {
			free(data);
			free(src);
			fputs("Failed brotli compression", stderr);
			return NULL;
		}
	}
	free(src);

	unsigned char bodyHash[crypto_hash_sha256_BYTES];
	if (crypto_hash_sha256(bodyHash, (unsigned char*)data, lenData) != 0) {fputs("Hash failed", stderr); return NULL;}

	char bodyHashB64[sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(bodyHashB64, sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL), bodyHash, crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL);

	const char * const conn = onion? "://"AEM_ONIONID".onion" : "s://"AEM_DOMAIN;
	const char * const onionLoc = onion? "" : "Onion-Location: http://"AEM_ONIONID".onion\r\n";
	const char * const tlsHeaders = onion? "" : "Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n";

	// Headers
	char headers[4096];
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
			"frame-src"       " blob:;"
			"img-src"         " blob: data:;"
			"media-src"       " blob:;"
			"object-src"      " blob:;"
			"script-src"      " 'wasm-unsafe-eval';"
			"script-src-elem" " https://cdn.jsdelivr.net/gh/emp-code/ https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdn.jsdelivr.net/gh/jedisct1/libsodium.js@0.7.10/dist/browsers/sodium.js;"
			"style-src-attr"  " 'unsafe-inline';" // For displaying PDF files
			"style-src-elem"  " https://cdn.jsdelivr.net/gh/emp-code/ 'unsafe-inline';" // inline for displaying HTML files

			"base-uri"        " 'none';"
			"child-src"       " 'none';"
			"default-src"     " 'none';"
			"font-src"        " 'none';"
			"form-action"     " 'none';"
			"frame-ancestors" " 'none';"
			"manifest-src"    " 'none';"
			"prefetch-src"    " 'none';"
			"script-src-attr" " 'none';"
			"worker-src"      " 'none';"
		"\r\n"

		// DP
		// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/blink/renderer/core/permissions_policy/document_policy_features.json5
		"Document-Policy: "
			"document-domain=?0,"
			"document-write=?0,"
			"font-display-late-swap=?0,"
			"force-load-at-top,"
			"js-profiling=?0,"
			"layout-animations=?0,"
			"sync-script,"
			"sync-xhr=?0,"
			"unsized-media"
		"\r\n"

		"Require-Document-Policy: "
			"document-domain=?0,"
			"document-write=?0,"
			"font-display-late-swap=?0,"
			"force-load-at-top,"
			"js-profiling=?0,"
			"layout-animations=?0,"
			"lossless-images-max-bpp=0,"
			"lossless-images-strict-max-bpp=0,"
			"lossy-images-max-bpp=0,"
			"oversized-images=0,"
			"sync-script=?0,"
			"sync-xhr=?0,"
			"unsized-media=?0"
		"\r\n"

		// PP
		// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/blink/renderer/core/permissions_policy/permissions_policy_features.json5
		// https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/blink/web_tests/webexposed/feature-policy-features-expected.txt
		"Permissions-Policy: "
			"clipboard-write"                 "=(self),"
			"cross-origin-isolated"           "=(self),"
			"focus-without-user-activation"   "=(self),"
			"fullscreen"                      "=(self),"
			"vertical-scroll"                 "=(*),"

			"accelerometer"                   "=(),"
			"ambient-light-sensor"            "=(),"
			"attribution-reporting"           "=(),"
			"autoplay"                        "=(),"
			"bluetooth"                       "=(),"
			"camera"                          "=(),"
			"ch-device-memory"                "=(),"
			"ch-downlink"                     "=(),"
			"ch-dpr"                          "=(),"
			"ch-ect"                          "=(),"
			"ch-prefers-color-scheme"         "=(),"
			"ch-rtt"                          "=(),"
			"ch-save-data"                    "=(),"
			"ch-ua"                           "=(),"
			"ch-ua-arch"                      "=(),"
			"ch-ua-bitness"                   "=(),"
			"ch-ua-full-version"              "=(),"
			"ch-ua-full-version-list"         "=(),"
			"ch-ua-mobile"                    "=(),"
			"ch-ua-model"                     "=(),"
			"ch-ua-platform"                  "=(),"
			"ch-ua-platform-version"          "=(),"
			"ch-ua-wow64"                     "=(),"
			"ch-viewport-height"              "=(),"
			"ch-viewport-width"               "=(),"
			"ch-width"                        "=(),"
			"clipboard-read"                  "=(),"
			"display-capture"                 "=(),"
			"document-domain"                 "=(),"
			"encrypted-media"                 "=(),"
			"execution-while-not-rendered"    "=(),"
			"execution-while-out-of-viewport" "=(),"
			"gamepad"                         "=(),"
			"geolocation"                     "=(),"
			"gyroscope"                       "=(),"
			"hid"                             "=(),"
			"idle-detection"                  "=(),"
			"interest-cohort"                 "=(),"
			"keyboard-map"                    "=(),"
			"local-fonts"                     "=(),"
			"magnetometer"                    "=(),"
			"microphone"                      "=(),"
			"midi"                            "=(),"
			"otp-credentials"                 "=(),"
			"payment"                         "=(),"
			"picture-in-picture"              "=(),"
			"publickey-credentials-get"       "=(),"
			"screen-wake-lock"                "=(),"
			"serial"                          "=(),"
			"shared-autofill"                 "=(),"
			"sync-xhr"                        "=(),"
			"trust-token-redemption"          "=(),"
			"usb"                             "=(),"
			"web-share"                       "=(),"
			"window-placement"                "=(),"
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
	if (result == NULL) {free(data); return NULL;}
	memcpy(result, headers, lenHeaders);
	memcpy(result + lenHeaders, data, lenData);
	free(data);

	return result;
}

static void printSts(void) {
	unsigned char tmp[512];
	sprintf((char*)tmp,
		"HTTP/1.1 200 aem\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Connection: close\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
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

	const size_t len = strlen((char*)tmp);
	printf("#define AEM_MTASTS_SIZE %zu\n", len);
	printDef("AEM_MTASTS_DATA", tmp, len);
	puts("");
}

int main(int argc, char *argv[]) {
	if (argc != 2) {fprintf(stderr, "Usage: %s input.html\n", argv[0]); return EXIT_FAILURE;}
	if (sodium_init() < 0) {fputs("Terminating: Failed sodium_init()", stderr); return EXIT_FAILURE;}

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
	if (html_clr_data == NULL) return EXIT_FAILURE;
	printf("#define AEM_HTML_CLR_SIZE %zu\n", html_clr_size);
	printDef("AEM_HTML_CLR_DATA", html_clr_data, html_clr_size);
	puts("");
	free(html_clr_data);

	size_t html_oni_size;
	unsigned char * const html_oni_data = genHtml(html, lenHtml, &html_oni_size, true);
	if (html_oni_data == NULL) return EXIT_FAILURE;
	printf("#define AEM_HTML_ONI_SIZE %zu\n", html_oni_size);
	printDef("AEM_HTML_ONI_DATA", html_oni_data, html_oni_size);
	puts("");
	free(html_oni_data);

	puts("#endif");

	return EXIT_SUCCESS;
}
