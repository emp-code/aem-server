#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <brotli/encode.h>
#include <sodium.h>

#include "../Global.h"
#include "../Common/GetKey.h"

static unsigned char *genWeb(const unsigned char * const src, const size_t lenSrc, size_t * const lenResult, const bool onion) {
	unsigned char * const comp = malloc(lenSrc);
	if (comp == NULL) {
		fputs("Failed malloc", stderr);
		return NULL;
	}

	size_t lenComp = lenSrc;
	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, lenSrc, src, &lenComp, comp) == BROTLI_FALSE) {
		fputs("Failed Brotli compression", stderr);
		free(comp);
		return NULL;
	}

	const char * const conn = onion? "://[Placeholder for the 56 characters of the Onion domain.].onion" : "s://[Placeholder for the API Domain]";
	const char * const onionLoc = "";//onion? "" : "Onion-Location: http://[Placeholder for the 56 characters of the Onion domain.].onion\r\n";
	const char * const tlsHeaders = onion? "" : "Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n";

	// Headers
	char headers[4096];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"

		// General headers
		"Cache-Control: public, max-age=999, immutable\r\n" // ~15min
		"Connection: close\r\n"
		"Content-Encoding: br\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"%s"

		// CSP
		"Content-Security-Policy: "
			"connect-src"     " http%s:302 data:;"
			"frame-src"       " blob:;"
			"img-src"         " blob: data:;"
			"media-src"       " blob:;"
			"object-src"      " blob:;"
			"script-src"      " 'wasm-unsafe-eval';"
			"script-src-elem" " https://cdn.jsdelivr.net/gh/emp-code/ https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdn.jsdelivr.net/gh/jedisct1/libsodium.js@0.7.13/dist/browsers-sumo/sodium.js;"
			"style-src-attr"  " 'unsafe-inline';" // For displaying PDF files
			"style-src-elem"  " https://cdn.jsdelivr.net/gh/emp-code/ 'unsafe-inline';" // inline for displaying HTML files

			"base-uri"        " 'none';"
			"child-src"       " 'none';"
			"default-src"     " 'none';"
			"font-src"        " 'none';"
			"form-action"     " 'none';"
			"frame-ancestors" " 'none';"
			"manifest-src"    " 'none';"
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
			"browsing-topics"                 "=(),"
			"camera"                          "=(),"
			"captured-surface-control"        "=(),"
			"ch-device-memory"                "=(),"
			"ch-downlink"                     "=(),"
			"ch-dpr"                          "=(),"
			"ch-ect"                          "=(),"
			"ch-prefers-color-scheme"         "=(),"
			"ch-prefers-reduced-motion"       "=(),"
			"ch-prefers-reduced-transparency" "=(),"
			"ch-rtt"                          "=(),"
			"ch-save-data"                    "=(),"
			"ch-ua-arch"                      "=(),"
			"ch-ua-bitness"                   "=(),"
			"ch-ua-form-factors"              "=(),"
			"ch-ua-full-version-list"         "=(),"
			"ch-ua-full-version"              "=(),"
			"ch-ua-mobile"                    "=(),"
			"ch-ua-model"                     "=(),"
			"ch-ua-platform-version"          "=(),"
			"ch-ua-platform"                  "=(),"
			"ch-ua-wow64"                     "=(),"
			"ch-ua"                           "=(),"
			"ch-viewport-height"              "=(),"
			"ch-viewport-width"               "=(),"
			"ch-width"                        "=(),"
			"clipboard-read"                  "=(),"
			"compute-pressure"                "=(),"
			"direct-sockets"                  "=(),"
			"display-capture"                 "=(),"
			"document-domain"                 "=(),"
			"encrypted-media"                 "=(),"
			"execution-while-not-rendered"    "=(),"
			"execution-while-out-of-viewport" "=(),"
			"gamepad"                         "=(),"
			"geolocation"                     "=(),"
			"gyroscope"                       "=(),"
			"hid"                             "=(),"
			"identity-credentials-get"        "=(),"
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
			"private-aggregation"             "=(),"
			"private-state-token-issuance"    "=(),"
			"private-state-token-redemption"  "=(),"
			"publickey-credentials-create"    "=(),"
			"publickey-credentials-get"       "=(),"
			"screen-wake-lock"                "=(),"
			"serial"                          "=(),"
			"shared-storage"                  "=(),"
			"shared-storage-select-url"       "=(),"
			"speaker-selection"               "=(),"
			"storage-access"                  "=(),"
			"sync-xhr"                        "=(),"
			"unload"                          "=(),"
			"usb-unrestricted"                "=(),"
			"usb"                             "=(),"
			"web-share"                       "=(),"
			"window-management"               "=(),"
			"xr-spatial-tracking"             "=()"
		"\r\n"

		// Misc security headers
		"%s"
		"Cross-Origin-Embedder-Policy: require-corp\r\n"
		"Cross-Origin-Opener-Policy: same-origin\r\n"
		"Cross-Origin-Resource-Policy: same-origin\r\n"
		"Referrer-Policy: no-referrer\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-DNS-Prefetch-Control: off\r\n"
		"X-Frame-Options: deny\r\n"
		"X-XSS-Protection: 1; mode=block\r\n"
		"\r\n"
	, lenComp, // Content-Length
	onionLoc,
	conn, // CSP connect
	tlsHeaders
	);

	const size_t lenHeaders = strlen(headers);

	*lenResult = lenHeaders + lenComp;
	unsigned char * const result = malloc(*lenResult);
	if (result == NULL) {free(comp); return NULL;}
	memcpy(result, headers, lenHeaders);
	memcpy(result + lenHeaders, comp, lenComp);
	free(comp);

	return result;
}

static void writeWeb(const unsigned char * const src, const size_t lenSrc, const unsigned char launchKey[crypto_aead_aegis256_KEYBYTES], const bool onion) {
	size_t lenDec;
	unsigned char * const dec = genWeb(src, lenSrc, &lenDec, onion);
	if (dec == NULL) return;

	const size_t lenEnc = lenDec + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	if (crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, lenDec, NULL, 0, NULL, enc, launchKey) != 0) {
		fputs("Failed encrypting", stderr);
		free(dec);
		return;
	}
	free(dec);

	const int fd = open("/var/lib/allears/Data/web-clr", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd < 0) {
		fprintf(stderr, "Failed opening file: %m\n");
		close(fd);
		return;
	}

	if (write(fd, enc, lenEnc) != (ssize_t)lenEnc) {
		fprintf(stderr, "Failed writing file: %m\n");
		close(fd);
		return;
	}

	close(fd);
	puts("Created /var/lib/allears/Data/web-clr");
	return;
}

static int getLaunchKey(unsigned char launchKey[crypto_aead_aegis256_KEYBYTES]) {
	unsigned char smk[AEM_KDF_SMK_KEYLEN];
	if (getKey(smk) != 0) {puts("Failed reading key"); return -1;}
	aem_kdf_smk(launchKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_SMK_LCH, smk);
	sodium_memzero(smk, AEM_KDF_SMK_KEYLEN);
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {fprintf(stderr, "Usage: %s input.html\n", argv[0]); return EXIT_FAILURE;}
	if (sodium_init() != 0) {fputs("Failed sodium_init()", stderr); return EXIT_FAILURE;}

	unsigned char launchKey[crypto_aead_aegis256_KEYBYTES];
	if (getLaunchKey(launchKey) != 0) return EXIT_FAILURE;

	const int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {fprintf(stderr, "Failed opening file: %m\n"); return EXIT_FAILURE;}

	const off_t lenSrc = lseek(fd, 0, SEEK_END);
	if (lenSrc < 1) {fputs("Input file is empty", stderr); return EXIT_FAILURE;}
	if (lenSrc > 99999) {fputs("Input file too large", stderr); return EXIT_FAILURE;}

	unsigned char src[lenSrc];
	if (pread(fd, src, lenSrc, 0) != (ssize_t)lenSrc) {
		fprintf(stderr, "Failed reading file: %m\n");
		close(fd);
		return EXIT_FAILURE;
	}
	close(fd);

	writeWeb(src, lenSrc, launchKey, false); // Clear
//	writeWeb(src, lenSrc, launchKey, true); // Onion

	return EXIT_SUCCESS;
}
