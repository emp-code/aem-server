/*
	All-Ears Manager

	Protocol:
		All messages are AEM_LEN_MSG bytes in cleartext, and are encrypted with crypto_secretbox_easy

		1. Client sends message containing instructions (if any)
		2. Server processes instructions, if any (spawn/terminate/kill an All-Ears process)
		3. Server responds with message containing information about All-Ears processes

	The encryption is mostly for authentication. There is no forward secrecy.
*/

#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h> // for memfd_create()
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/x509_crt.h>
#include <sodium.h>
#include <zopfli/zopfli.h>

#include "../Common/Brotli.c"
#include "../Global.h"

#include "mount.h"

#include "manager.h"

#define AEM_SOCKET_TIMEOUT 10

#define AEM_MAXPROCESSES 25
#define AEM_LEN_MSG 1024 // must be at least AEM_MAXPROCESSES * 3 * 4
#define AEM_LEN_ENCRYPTED (AEM_LEN_MSG + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define AEM_STACKSIZE 1048576 // 1 MiB

#define AEM_PATH_CONF "/etc/allears"

#define AEM_PATH_KEY_ACC AEM_PATH_CONF"/Account.key"
#define AEM_PATH_KEY_API AEM_PATH_CONF"/API.key"
#define AEM_PATH_KEY_MNG AEM_PATH_CONF"/Manager.key"
#define AEM_PATH_KEY_SIG AEM_PATH_CONF"/Signing.key"
#define AEM_PATH_KEY_STO AEM_PATH_CONF"/Storage.key"

#define AEM_PATH_DKI_ADM AEM_PATH_CONF"/Admin.dkim"
#define AEM_PATH_DKI_USR AEM_PATH_CONF"/Users.dkim"

#define AEM_PATH_SLT_NRM AEM_PATH_CONF"/Normal.slt"
#define AEM_PATH_SLT_SHD AEM_PATH_CONF"/Shield.slt"
#define AEM_PATH_SLT_FKE AEM_PATH_CONF"/Fake.slt"

#define AEM_PATH_TLS_CRT AEM_PATH_CONF"/TLS.crt"
#define AEM_PATH_TLS_KEY AEM_PATH_CONF"/TLS.key"

#define AEM_PATH_ADR_ADM AEM_PATH_CONF"/Admin.adr"
#define AEM_PATH_HTML AEM_PATH_CONF"/index.html"

#define AEM_LEN_FILE_MAX 8192
#define AEM_LEN_FIL2_MAX 65536

static unsigned char master[AEM_LEN_KEY_MASTER];

static int binfd[AEM_PROCESSTYPES_COUNT] = {0,0,0,0,0,0,0,0};

static unsigned char accessKey_account_api[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_account_mta[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage_api[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage_mta[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_enquiry_all[AEM_LEN_ACCESSKEY];

static unsigned char key_acc[AEM_LEN_KEY_ACC];
static unsigned char key_api[AEM_LEN_KEY_API];
static unsigned char key_mng[AEM_LEN_KEY_MNG];
static unsigned char key_sig[AEM_LEN_KEY_SIG];
static unsigned char key_sto[AEM_LEN_KEY_STO];

static unsigned char dki_adm[AEM_LEN_KEY_DKI];
static unsigned char dki_usr[AEM_LEN_KEY_DKI];

static unsigned char slt_nrm[AEM_LEN_SALT_NORM];
static unsigned char slt_shd[AEM_LEN_SALT_SHLD];
static unsigned char slt_fke[AEM_LEN_SALT_FAKE];

static unsigned char tls_crt[AEM_LEN_FILE_MAX];
static unsigned char tls_key[AEM_LEN_FILE_MAX];
static size_t len_tls_crt;
static size_t len_tls_key;

static unsigned char adr_adm[AEM_LEN_FIL2_MAX];
static unsigned char html[AEM_LEN_FILE_MAX];
static unsigned char html_oni[AEM_LEN_FILE_MAX];
static size_t len_adr_adm;
static size_t len_html;
static size_t len_html_oni;

static char onionId[56];
static char domain[AEM_MAXLEN_DOMAIN];
static size_t lenDomain;

const int typeNice[AEM_PROCESSTYPES_COUNT] = AEM_NICE;

struct aem_process {
	pid_t pid;
	unsigned char *stack;
};

static struct aem_process aemProc[5][AEM_MAXPROCESSES];

static pid_t pid_account = 0;
static pid_t pid_storage = 0;
static pid_t pid_enquiry = 0;
static unsigned char *stack_account;
static unsigned char *stack_storage;
static unsigned char *stack_enquiry;

static unsigned char encrypted[AEM_LEN_ENCRYPTED];
static unsigned char decrypted[AEM_LEN_MSG];

static int sockMain = -1;
static int sockClient = -1;

static bool terminate = false;

// For handling large writes on O_DIRECT pipes
static int pipeWriteDirect(const int fd, const unsigned char * const data, const size_t len) {
	size_t written = 0;

	while (len - written > PIPE_BUF) {
		const ssize_t ret = write(fd, data + written, len - written);
		if (ret < 1) return -1;
		written += len;
	}

	return write(fd, data + written, len - written);
}

static int getOnionId(void) {
	const int fd = open("/var/lib/tor/hidden_service/hostname", O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
	if (fd < 0 || read(fd, onionId, 56) != 56) {
		close(fd);
		syslog(LOG_ERR, "Failed reading onionId");
		return -1;
	}

	close(fd);
	return 0;
}

void setMasterKey(const unsigned char newKey[crypto_secretbox_KEYBYTES]) {
	memcpy(master, newKey, crypto_secretbox_KEYBYTES);
}

void setAccessKeys(void) {
	randombytes_buf(accessKey_account_api, AEM_LEN_ACCESSKEY);
	randombytes_buf(accessKey_account_mta, AEM_LEN_ACCESSKEY);
	randombytes_buf(accessKey_storage_api, AEM_LEN_ACCESSKEY);
	randombytes_buf(accessKey_storage_mta, AEM_LEN_ACCESSKEY);
	randombytes_buf(accessKey_enquiry_all, AEM_LEN_ACCESSKEY);
}

void wipeKeys(void) {
	sodium_memzero(master, AEM_LEN_KEY_MASTER);

	sodium_memzero(accessKey_account_api, AEM_LEN_ACCESSKEY);
	sodium_memzero(accessKey_account_mta, AEM_LEN_ACCESSKEY);
	sodium_memzero(accessKey_storage_api, AEM_LEN_ACCESSKEY);
	sodium_memzero(accessKey_storage_mta, AEM_LEN_ACCESSKEY);
	sodium_memzero(accessKey_enquiry_all, AEM_LEN_ACCESSKEY);

	sodium_memzero(key_acc, AEM_LEN_KEY_ACC);
	sodium_memzero(key_api, AEM_LEN_KEY_API);
	sodium_memzero(key_mng, AEM_LEN_KEY_MNG);
	sodium_memzero(key_sig, AEM_LEN_KEY_SIG);
	sodium_memzero(key_sto, AEM_LEN_KEY_STO);

	sodium_memzero(slt_nrm, AEM_LEN_SALT_NORM);
	sodium_memzero(slt_shd, AEM_LEN_SALT_SHLD);
	sodium_memzero(slt_fke, AEM_LEN_SALT_FAKE);

	sodium_memzero(tls_crt, len_tls_crt);
	sodium_memzero(tls_key, len_tls_key);

	sodium_memzero(adr_adm, len_adr_adm);
	sodium_memzero(html, len_html);
	sodium_memzero(html_oni, len_html_oni);

	len_tls_crt = 0;
	len_tls_key = 0;
	len_adr_adm = 0;
	len_html = 0;
	len_html_oni = 0;

	sodium_memzero(encrypted, AEM_LEN_ENCRYPTED);
	sodium_memzero(decrypted, AEM_LEN_MSG);
}

static bool process_verify(const pid_t pid) {
	if (pid < 1) return false;

	char path[22];
	sprintf(path, "/proc/%u/stat", pid);
	const int fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
	if (fd < 0) return false;

	char buf[41];
	const off_t bytes = read(fd, buf, 41);
	close(fd);
	if (bytes < 41) return false;

	const char *c = memchr(buf, ' ', 41);
	if (c == NULL || c - buf > 11) return false;
	c++;
	if (*c != '(') return false;

	c = strchr(c + 1, ' ');
	if (c == NULL || c - buf > 29) return false;
	c++;
	if (*c != 'R' && *c != 'S') return false;
	c++;
	if (*c != ' ') return false;
	c++;

	if (strtol(c, NULL, 10) != getpid()) return false;

	return true;
}

static void refreshPids(void) {
	for (int type = 0; type < 5; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemProc[type][i].pid != 0 && !process_verify(aemProc[type][i].pid)) {
				sodium_free(aemProc[type][i].stack);
				aemProc[type][i].pid = 0;
			}
		}
	}

	if (pid_account != 0 && !process_verify(pid_account)) {
		sodium_free(stack_account);
		pid_account = 0;
	}

	if (pid_storage != 0 && !process_verify(pid_storage)) {
		sodium_free(stack_storage);
		pid_storage = 0;
	}

	if (pid_enquiry != 0 && !process_verify(pid_enquiry)) {
		sodium_free(stack_enquiry);
		pid_enquiry = 0;
	}
}

// SIGUSR1 = Allow processing one more connection; SIGUSR2 = Immediate termination
void killAll(int sig) {
	wipeKeys();
	refreshPids();

	if (sig != SIGUSR1 && sig != SIGUSR2) sig = SIGUSR1;

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemProc[type][i].pid > 0) kill(aemProc[type][i].pid, sig); // Request process to terminate
		}
	}

	if (sig == SIGUSR1) {
		// TODO: Connect to each service to make sure they'll terminate
	} else {
		if (pid_account > 0) kill(pid_account, SIGUSR2);
		if (pid_storage > 0) kill(pid_storage, SIGUSR2);
		if (pid_enquiry > 0) kill(pid_enquiry, SIGUSR2);
	}

	// Processes should have terminated after one second
	sleep(1);
	refreshPids();

	if (sig == SIGUSR1) {
		for (int type = 0; type < 3; type++) {
			for (int i = 0; i < AEM_MAXPROCESSES; i++) {
				if (aemProc[type][i].pid > 0) kill(aemProc[type][i].pid, SIGUSR2);
			}
		}

		if (pid_account > 0) kill(pid_account, SIGUSR1);
		if (pid_storage > 0) kill(pid_storage, SIGUSR1);
		if (pid_enquiry > 0) kill(pid_enquiry, SIGUSR1);

		sleep(1);
		refreshPids();
	}

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemProc[type][i].pid > 0) kill(aemProc[type][i].pid, SIGKILL);
		}
	}

	if (pid_account > 0) kill(pid_account, SIGUSR2);
	if (pid_storage > 0) kill(pid_storage, SIGUSR2);
	if (pid_enquiry > 0) kill(pid_enquiry, SIGUSR2);

	sleep(1);
	refreshPids();

	if (pid_account > 0) kill(pid_account, SIGKILL);
	if (pid_storage > 0) kill(pid_storage, SIGKILL);
	if (pid_enquiry > 0) kill(pid_enquiry, SIGKILL);

	umount2(AEM_MOUNTDIR, MNT_DETACH);
	exit(EXIT_SUCCESS);
}

__attribute__((warn_unused_result))
static int getDomainFromCert(void) {
	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	int ret = mbedtls_x509_crt_parse(&crt, tls_crt, len_tls_crt);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_x509_crt_parse failed: %x", ret); return -1;}

	char certInfo[1024];
	mbedtls_x509_crt_info(certInfo, 1024, "AEM_", &crt);

	const char *c = strstr(certInfo, "\nAEM_subject name");
	if (c == NULL) return -1;
	c += 17;

	const char * const end = strchr(c, '\n');

	c = strstr(c, ": CN=");
	if (c == NULL || c > end) return -1;
	c += 5;

	const int len = end - c;
	if (len > AEM_MAXLEN_DOMAIN) return -1;

	memcpy(domain, c, len);
	lenDomain = len;
	return 0;
}

static int modHtml(unsigned char * const src, const size_t lenSrc) {
	unsigned char *placeholder = memmem(src, lenSrc, "All-Ears Mail API PublicKey placeholder, replaced automatically.", 64);
	if (placeholder == NULL) {syslog(LOG_ERR, "API-Placeholder not found"); return -1;}
	unsigned char api_tmp[crypto_box_SECRETKEYBYTES];
	unsigned char api_pub[crypto_box_PUBLICKEYBYTES];
	char api_hex[65];
	crypto_box_seed_keypair(api_pub, api_tmp, key_api);
	sodium_memzero(api_tmp, crypto_box_SECRETKEYBYTES);
	sodium_bin2hex(api_hex, 65, api_pub, crypto_box_PUBLICKEYBYTES);
	memcpy(placeholder, api_hex, crypto_box_PUBLICKEYBYTES * 2);

	placeholder = memmem(src, lenSrc, "All-Ears Mail Sig PublicKey placeholder, replaced automatically.", 64);
	if (placeholder == NULL) {syslog(LOG_ERR, "Sig-Placeholder not found"); return -1;}
	unsigned char sig_tmp[crypto_sign_SECRETKEYBYTES];
	unsigned char sig_pub[crypto_sign_PUBLICKEYBYTES];
	char sig_hex[65];
	crypto_sign_seed_keypair(sig_pub, sig_tmp, key_sig);
	sodium_memzero(sig_tmp, crypto_sign_SECRETKEYBYTES);
	sodium_bin2hex(sig_hex, 65, sig_pub, crypto_sign_PUBLICKEYBYTES);
	memcpy(placeholder, sig_hex, crypto_sign_PUBLICKEYBYTES * 2);

	placeholder = memmem(src, lenSrc, "AEM Normal Addr Salt placeholder", 32);
	if (placeholder == NULL) {syslog(LOG_ERR, "Slt-Placeholder not found"); return -1;}
	char slt_hex[33];
	sodium_bin2hex(slt_hex, 33, slt_nrm, AEM_LEN_SALT_NORM);
	memcpy(placeholder, slt_hex, AEM_LEN_SALT_NORM * 2);

	return 0;
}

// Add email domain (onion service)
static int emlHtml(unsigned char * const src, size_t * const lenSrc) {
	unsigned char * const placeholder = memmem(src, *lenSrc, "AEM placeholder for email domain", 32);
	if (placeholder == NULL) {syslog(LOG_ERR, "Eml-Placeholder not found"); return -1;}
	memcpy(placeholder, domain, lenDomain);
	memmove(placeholder + lenDomain, placeholder + 32, (src + *lenSrc) - (placeholder + 32));
	*lenSrc -= (32 - lenDomain);

	return 0;
}

// Remove email domain (clearnet)
static int emrHtml(unsigned char * const src, size_t * const lenSrc) {
	unsigned char * const placeholder = memmem(src, *lenSrc, "aeemldom=\"", 10);
	if (placeholder == NULL) {syslog(LOG_ERR, "Emr-Placeholder not found"); return -1;}
	memmove(placeholder + 10, placeholder + 10 + lenDomain, (src + *lenSrc) - (placeholder + 10 + lenDomain));
	*lenSrc -= (lenDomain);

	return 0;
}

static int genHtml(const unsigned char * const src, const size_t lenSrc, const bool onion) {
	unsigned char *data;
	size_t lenData;
	// Compression
	if (onion) { // Zopfli (deflate)
		ZopfliOptions zopOpt;
		ZopfliInitOptions(&zopOpt);

		lenData = 0;
		data = 0;

		ZopfliCompress(&zopOpt, ZOPFLI_FORMAT_DEFLATE, src, lenSrc, &data, &lenData);
		if (data == 0 || lenData < 1) {
			syslog(LOG_ERR, "Failed zopfli compression");
			return -1;
		}
	} else { // Brotli, HTTPS-only
		data = malloc(lenSrc);
		if (data == NULL) {
			syslog(LOG_ERR, "Failed allocation");
			return -1;
		}

		memcpy(data, src, lenSrc);
		lenData = lenSrc;

		if (brotliCompress(&data, &lenData) != 0) {
			free(data);
			syslog(LOG_ERR, "Failed brotli compression");
			return -1;
		}
	}

	unsigned char bodyHash[32];
	if (crypto_hash_sha256(bodyHash, (unsigned char*)data, lenData) != 0) {syslog(LOG_ERR, "Hash failed"); return -1;}

	char bodyHashB64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL) + 1];
	sodium_bin2base64(bodyHashB64, sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL) + 1, bodyHash, 32, sodium_base64_VARIANT_ORIGINAL);

	char conn[66];
	if (onion)
		sprintf(conn, "://%.56s.onion", onionId);
	else
		sprintf(conn, "s://%.*s", (int)lenDomain, domain);

	char onionLoc[89];
	if (onion)
		onionLoc[0] = '\0';
	else
		sprintf(onionLoc, "Onion-Location: http://%.56s.onion/\r\n", onionId);

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
		"Link: <https://%.*s>; rel=\"canonical\"\r\n"
		"%s"
		"Server: All-Ears Mail\r\n"
		"Tk: N\r\n"

		// CSP
		"Content-Security-Policy: "
			"connect-src"     " http%s:302/api data:;"
			"img-src"         " blob: data:;"
			"media-src"       " blob:;"
			"script-src"      " https://cdn.jsdelivr.net/gh/emp-code/ https://cdn.jsdelivr.net/gh/google/brotli@1.0.7/js/decode.min.js https://cdn.jsdelivr.net/gh/jedisct1/libsodium.js@0.7.6/dist/browsers/sodium.js 'unsafe-eval';"
			"style-src"       " https://cdn.jsdelivr.net/gh/emp-code/;"

			"base-uri"        " 'none';"
			"child-src"       " 'none';"
			"default-src"     " 'none';"
			"font-src"        " 'none';"
			"form-action"     " 'none';"
			"frame-ancestors" " 'none';"
			"frame-src"       " 'none';"
			"manifest-src"    " 'none';"
			"object-src"      " 'none';"
			"prefetch-src"    " 'none';"
			"worker-src"      " 'none';"

			"block-all-mixed-content;"
			"sandbox allow-scripts allow-same-origin;"
		"\r\n"

		// FP
		"Feature-Policy: "
			"accelerometer"                   " 'none';"
			"ambient-light-sensor"            " 'none';"
			"autoplay"                        " 'none';"
			"battery"                         " 'none';"
			"camera"                          " 'none';"
			"display-capture"                 " 'none';"
			"document-domain"                 " 'none';"
			"document-write"                  " 'none';"
			"encrypted-media"                 " 'none';"
			"execution-while-not-rendered"    " 'none';"
			"execution-while-out-of-viewport" " 'none';"
			"fullscreen"                      " 'none';"
			"geolocation"                     " 'none';"
			"gyroscope"                       " 'none';"
			"layout-animations"               " 'none';"
			"legacy-image-formats"            " 'none';"
			"magnetometer"                    " 'none';"
			"microphone"                      " 'none';"
			"midi"                            " 'none';"
			"navigation-override"             " 'none';"
			"oversized-images"                " 'none';"
			"payment"                         " 'none';"
			"picture-in-picture"              " 'none';"
			"publickey-credentials"           " 'none';"
			"speaker"                         " 'none';"
			"sync-xhr"                        " 'none';"
			"usb"                             " 'none';"
			"vibrate"                         " 'none';"
			"vr"                              " 'none';"
			"wake-lock"                       " 'none';"
			"xr-spatial-tracking"             " 'none';"
		"\r\n"

		// Security headers
		"%s"
		"Cross-Origin-Embedder-Policy: require-corp\r\n"
		"Cross-Origin-Opener-Policy: same-origin\r\n"
		"Digest: sha-256=%s\r\n"
		"Referrer-Policy: no-referrer\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-DNS-Prefetch-Control: off\r\n"
		"X-Frame-Options: deny\r\n"
		"X-XSS-Protection: 1; mode=block\r\n"
		"\r\n"
	, onion? "deflate" : "br", // Content-Encoding
	lenData, // Content-Length
	(int)lenDomain, domain, // Canonical
	onionLoc,
	conn, // CSP connect
	tlsHeaders,
	bodyHashB64); // Digest

	const size_t lenHeaders = strlen(headers);

	if (onion) {
		memcpy(html_oni, headers, lenHeaders);
		memcpy(html_oni + lenHeaders, data, lenData);
		len_html_oni = lenHeaders + lenData;
	} else {
		memcpy(html, headers, lenHeaders);
		memcpy(html + lenHeaders, data, lenData);
		len_html = lenHeaders + lenData;
	}

	free(data);
	return 0;
}

static int loadFile(const char * const path, unsigned char * const target, size_t * const len, const off_t expectedLen, const off_t maxLen) {
	const int fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening file: %s", path); return -1;}

	off_t bytes = lseek(fd, 0, SEEK_END);
	if (bytes < 1 || bytes > maxLen - crypto_secretbox_NONCEBYTES || (expectedLen != 0 && bytes != expectedLen + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)) {
		syslog(LOG_ERR, "Invalid length for file: %s", path);
		close(fd);
		return -1;
	}
	lseek(fd, 0, SEEK_SET);

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	off_t readBytes = read(fd, nonce, crypto_secretbox_NONCEBYTES);
	if (readBytes != crypto_secretbox_NONCEBYTES) {syslog(LOG_ERR, "Failed reading nonce for file: %s", path); close(fd); return -1;}
	bytes -= crypto_secretbox_NONCEBYTES;

	unsigned char enc[bytes];
	readBytes = read(fd, enc, bytes);
	close(fd);
	if (readBytes != bytes) {syslog(LOG_ERR, "Failed reading file: %s", path); return -1;}

	if (len != NULL) *len = bytes - crypto_secretbox_MACBYTES;

	if (crypto_secretbox_open_easy(target, enc, bytes, nonce, master) != 0) {
		syslog(LOG_ERR, "Failed decrypting file: %s", path);
		return -1;
	}

	if (target == tls_crt) return getDomainFromCert();
	return 0;
}

static int loadExec(void) {
	const char * const path[] = AEM_PATH_EXE;

	unsigned char * const tmp = sodium_malloc(524288);
	size_t lenTmp;

	for (int i = 0; i < AEM_PROCESSTYPES_COUNT; i++) {
		if (loadFile(path[i], tmp, &lenTmp, 0, 524288) != 0) {
			sodium_free(tmp);
			return -1;
		}

		binfd[i] = memfd_create("aem", MFD_CLOEXEC | MFD_ALLOW_SEALING);

		if (write(binfd[i], tmp, lenTmp) != (ssize_t)lenTmp) {
			sodium_free(tmp);
			return -1;
		}

		fcntl(binfd[i], F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
	}

	sodium_free(tmp);
	return 0;
}

int loadFiles(void) {
	if (getOnionId() != 0) return -1;
	if (loadExec() != 0) return -1;

	int ret = (
	   loadFile(AEM_PATH_KEY_ACC, key_acc, NULL, AEM_LEN_KEY_ACC, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_API, key_api, NULL, AEM_LEN_KEY_API, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_MNG, key_mng, NULL, AEM_LEN_KEY_MNG, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_SIG, key_sig, NULL, AEM_LEN_KEY_SIG, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_STO, key_sto, NULL, AEM_LEN_KEY_STO, AEM_LEN_FILE_MAX) == 0

	&& loadFile(AEM_PATH_DKI_ADM, dki_adm, NULL, AEM_LEN_KEY_DKI, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_DKI_USR, dki_usr, NULL, AEM_LEN_KEY_DKI, AEM_LEN_FILE_MAX) == 0

	&& loadFile(AEM_PATH_SLT_NRM, slt_nrm, NULL, AEM_LEN_SALT_NORM, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_SLT_SHD, slt_shd, NULL, AEM_LEN_SALT_SHLD, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_SLT_FKE, slt_fke, NULL, AEM_LEN_SALT_FAKE, AEM_LEN_FILE_MAX) == 0

	&& loadFile(AEM_PATH_TLS_CRT, tls_crt, &len_tls_crt, 0, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_TLS_KEY, tls_key, &len_tls_key, 0, AEM_LEN_FILE_MAX) == 0

	&& loadFile(AEM_PATH_ADR_ADM, adr_adm, &len_adr_adm, 0, AEM_LEN_FIL2_MAX) == 0
	) ? 0 : -1;
	if (ret != 0) return -1;

	unsigned char * const tmp = malloc(102400);
	if (tmp == NULL) return -1;
	size_t lenTmp = 0;
	if (loadFile(AEM_PATH_HTML, tmp, &lenTmp, 0, 102400) != 0) {free(tmp); return -1;}

	ret = (
	   modHtml(tmp, lenTmp) == 0
	&& emlHtml(tmp, &lenTmp) == 0 // Add email-domain
	&& genHtml(tmp, lenTmp, true) == 0 // Generate onion HTML
	&& emrHtml(tmp, &lenTmp) == 0 // Remove email-domain
	&& genHtml(tmp, lenTmp, false) == 0 // Generate clearnet HTML
	) ? 0 : -1;

	free(tmp);
	return ret;
}

static int setCaps(const int type) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	// Ambient capabilities
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return -1;

	cap_value_t cap;
	if (type == AEM_PROCESSTYPE_STORAGE || type == AEM_PROCESSTYPE_ACCOUNT || type == AEM_PROCESSTYPE_ENQUIRY) {
		cap = CAP_IPC_LOCK;
	} else {
		cap = CAP_NET_BIND_SERVICE;
	}

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) != 0) return -1;

	// Allow changing SecureBits for the next part
	const cap_value_t capPcap = CAP_SETPCAP;
	cap_t caps = cap_get_proc();
	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &capPcap, CAP_SET) != 0 || cap_set_proc(caps) != 0) return -1;

	// Disable and lock further ambient caps
	if (prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED | SECBIT_NOROOT | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED) != 0) {
		syslog(LOG_ERR, "Failed setting SecureBits");
		return -1;
	}

	// Disable all but the one capability needed
	return (
		cap_clear(caps) == 0
	&& cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_PERMITTED,   1, &cap, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_EFFECTIVE,   1, &cap, CAP_SET) == 0
	&& cap_set_proc(caps) == 0
	&& cap_free(caps) == 0
	) ? 0 : -1;
}

static int setSubLimits(const int type) {
	struct rlimit rlim;

	if (type != AEM_PROCESSTYPE_ACCOUNT && type != AEM_PROCESSTYPE_STORAGE) {
		rlim.rlim_cur = 0;
		rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_FSIZE, &rlim) != 0) return -1;
	}

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT: rlim.rlim_cur = 4; break;
		case AEM_PROCESSTYPE_STORAGE: rlim.rlim_cur = 5; break;
		case AEM_PROCESSTYPE_ENQUIRY: rlim.rlim_cur = 15; break;
		case AEM_PROCESSTYPE_MTA:     rlim.rlim_cur = 4; break;
		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI: rlim.rlim_cur = 3; break;
		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI: rlim.rlim_cur = 4; break;
	}

	rlim.rlim_max = rlim.rlim_cur;
	if (setrlimit(RLIMIT_OFILE, &rlim) != 0) return -1;

	rlim.rlim_cur = (typeNice[type] * -1) + 20; // The actual ceiling for the nice value is calculated as 20 - rlim_cur
	rlim.rlim_max = rlim.rlim_cur;
	return setrlimit(RLIMIT_NICE, &rlim);
}

__attribute__((warn_unused_result))
static int dropRoot(void) {
	const struct passwd * const p = getpwnam("allears");

	return (
	   p != NULL

	&& chroot(AEM_MOUNTDIR) == 0
	&& chdir("/") == 0

	&& setgroups(0, NULL) == 0
	&& setgid(p->pw_gid) == 0
	&& setuid(p->pw_uid) == 0

	&& getgid() == p->pw_gid
	&& getuid() == p->pw_uid
	) ? 0 : -1;
}

static int process_new(void *params) {
	wipeKeys();
	close(sockMain);
	close(sockClient);

	const int type = ((uint8_t*)params)[0];
	const int pipefd = ((uint8_t*)params)[1];
	const int closefd = ((uint8_t*)params)[2];
	close(closefd);

	for (int i = 0; i < AEM_PROCESSTYPES_COUNT; i++) {
		if (i != type) close(binfd[i]);
	}

	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, "") != 0) {syslog(LOG_ERR, "Failed private mount"); exit(EXIT_FAILURE);} // With CLONE_NEWNS, prevent propagation of mount events to other mount namespaces
	if (prctl(PR_SET_PDEATHSIG, SIGUSR2, 0, 0, 0) != 0) {syslog(LOG_ERR, "Failed prctl()"); exit(EXIT_FAILURE);}
	if (createMount(type) != 0) {syslog(LOG_ERR, "Failed createMount()"); exit(EXIT_FAILURE);}
	if (setSubLimits(type) != 0) {syslog(LOG_ERR, "Failed setSubLimits()"); exit(EXIT_FAILURE);}
	if (setpriority(PRIO_PROCESS, 0, typeNice[type]) != 0) {syslog(LOG_ERR, "Failed setpriority()"); exit(EXIT_FAILURE);}
	if (dropRoot() != 0) {syslog(LOG_ERR, "Failed dropRoot()"); exit(EXIT_FAILURE);}
	if (setCaps(type) != 0) {syslog(LOG_ERR, "Failed setCaps()"); exit(EXIT_FAILURE);}

	char arg1[] = {pipefd, '\0'};
	char * const newargv[] = {arg1, NULL};
	char * const emptyEnviron[] = {NULL};
	fexecve(binfd[type], newargv, emptyEnviron);

	// Only runs if exec failed
	syslog(LOG_ERR, "Failed starting process");
	exit(EXIT_FAILURE);
}

static void process_spawn(const int type) {
	int freeSlot = -1;
	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI || type == AEM_PROCESSTYPE_API_CLR || type == AEM_PROCESSTYPE_API_ONI) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemProc[type][i].pid == 0) {
				freeSlot = i;
				break;
			}
		}

		if (freeSlot < 0) return;
	}

	unsigned char * const stack = sodium_malloc(AEM_STACKSIZE);
	if (stack == NULL) return;
	bzero(stack, AEM_STACKSIZE);

	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI || type == AEM_PROCESSTYPE_API_CLR || type == AEM_PROCESSTYPE_API_ONI) {
		aemProc[type][freeSlot].stack = stack;
	} else if (type == AEM_PROCESSTYPE_ACCOUNT) {
		stack_account = stack;
	} else if (type == AEM_PROCESSTYPE_STORAGE) {
		stack_storage = stack;
	} else if (type == AEM_PROCESSTYPE_ENQUIRY) {
		stack_enquiry = stack;
	}

	int fd[2];
	if (pipe2(fd, O_DIRECT) < 0) {sodium_free(stack); return;}

	uint8_t params[] = {type, fd[0], fd[1]};
	int flags = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS | CLONE_UNTRACED; // CLONE_CLEAR_SIGHAND (Linux>=5.5)
	if (type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI) flags |= CLONE_NEWPID; // Doesn't interact with other processes

	pid_t pid = clone(process_new, stack + AEM_STACKSIZE, flags, params, NULL, NULL, NULL);
	if (pid < 0) {sodium_free(stack); return;}

	close(fd[0]);

	switch(type) {
		case AEM_PROCESSTYPE_ACCOUNT:
			if (
			   pipeWriteDirect(fd[1], key_acc, AEM_LEN_KEY_ACC) < 0

			|| pipeWriteDirect(fd[1], slt_nrm, AEM_LEN_SALT_NORM) < 0
			|| pipeWriteDirect(fd[1], slt_shd, AEM_LEN_SALT_SHLD) < 0
			|| pipeWriteDirect(fd[1], slt_fke, AEM_LEN_SALT_FAKE) < 0

			|| pipeWriteDirect(fd[1], accessKey_account_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_account_mta, AEM_LEN_ACCESSKEY) < 0

			|| pipeWriteDirect(fd[1], adr_adm, len_adr_adm) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_STORAGE:
			if (
			   pipeWriteDirect(fd[1], key_sto, AEM_LEN_KEY_STO) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_mta, AEM_LEN_ACCESSKEY) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_ENQUIRY:
			if (
			   pipeWriteDirect(fd[1], accessKey_enquiry_all, AEM_LEN_ACCESSKEY) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_MTA:
			if (
			   pipeWriteDirect(fd[1], (unsigned char*)&pid_account, sizeof(pid_t)) < 0
			|| pipeWriteDirect(fd[1], (unsigned char*)&pid_storage, sizeof(pid_t)) < 0

			|| pipeWriteDirect(fd[1], key_sig, AEM_LEN_KEY_SIG) < 0

			|| pipeWriteDirect(fd[1], accessKey_account_mta, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_mta, AEM_LEN_ACCESSKEY) < 0

			|| pipeWriteDirect(fd[1], tls_crt, len_tls_crt) < 0
			|| pipeWriteDirect(fd[1], tls_key, len_tls_key) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_WEB_CLR:
			if (
			   pipeWriteDirect(fd[1], tls_crt, len_tls_crt) < 0
			|| pipeWriteDirect(fd[1], tls_key, len_tls_key) < 0
			|| pipeWriteDirect(fd[1], html, len_html) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_WEB_ONI:
			if (pipeWriteDirect(fd[1], html_oni, len_html_oni) < 0)
				syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_API_CLR:
			if (
			   pipeWriteDirect(fd[1], (unsigned char*)&pid_account, sizeof(pid_t)) < 0
			|| pipeWriteDirect(fd[1], (unsigned char*)&pid_storage, sizeof(pid_t)) < 0
			|| pipeWriteDirect(fd[1], (unsigned char*)&pid_enquiry, sizeof(pid_t)) < 0

			|| pipeWriteDirect(fd[1], key_api, AEM_LEN_KEY_API) < 0
			|| pipeWriteDirect(fd[1], key_sig, AEM_LEN_KEY_SIG) < 0

			|| pipeWriteDirect(fd[1], dki_adm, AEM_LEN_KEY_DKI) < 0
			|| pipeWriteDirect(fd[1], dki_usr, AEM_LEN_KEY_DKI) < 0

			|| pipeWriteDirect(fd[1], accessKey_account_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_enquiry_all, AEM_LEN_ACCESSKEY) < 0

			|| pipeWriteDirect(fd[1], tls_crt, len_tls_crt) < 0
			|| pipeWriteDirect(fd[1], tls_key, len_tls_key) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_API_ONI:
			if (
			   pipeWriteDirect(fd[1], (unsigned char*)&pid_account, sizeof(pid_t)) < 0
			|| pipeWriteDirect(fd[1], (unsigned char*)&pid_storage, sizeof(pid_t)) < 0
			|| pipeWriteDirect(fd[1], (unsigned char*)&pid_enquiry, sizeof(pid_t)) < 0

			|| pipeWriteDirect(fd[1], key_api, AEM_LEN_KEY_API) < 0
			|| pipeWriteDirect(fd[1], key_sig, AEM_LEN_KEY_SIG) < 0

			|| pipeWriteDirect(fd[1], dki_adm, AEM_LEN_KEY_DKI) < 0
			|| pipeWriteDirect(fd[1], dki_usr, AEM_LEN_KEY_DKI) < 0

			|| pipeWriteDirect(fd[1], accessKey_account_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_enquiry_all, AEM_LEN_ACCESSKEY) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;
	}

	close(fd[1]);

	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI || type == AEM_PROCESSTYPE_API_CLR || type == AEM_PROCESSTYPE_API_ONI) {
		aemProc[type][freeSlot].pid = pid;
	}
	else if (type == AEM_PROCESSTYPE_ACCOUNT) pid_account = pid;
	else if (type == AEM_PROCESSTYPE_STORAGE) pid_storage = pid;
	else if (type == AEM_PROCESSTYPE_ENQUIRY) pid_enquiry = pid;

}

static void process_kill(const int type, const pid_t pid, const int sig) {
	syslog(LOG_INFO, "Termination of process %d requested", pid);
	if (type < 0 || type > 2 || pid < 1) return;

	bool found = false;
	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (aemProc[type][i].pid == pid) {
			found = true;
			break;
		}
	}

	if (!found) {syslog(LOG_INFO, "Process %d was not found", pid); return;}
	if (!process_verify(pid)) {syslog(LOG_INFO, "Process %d not valid", pid); return;}

	kill(pid, sig);
}

void cryptSend(const int sock) {
	refreshPids();

	bzero(decrypted, AEM_LEN_MSG);

	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < AEM_MAXPROCESSES; j++) {
			const int start = ((i * AEM_MAXPROCESSES) + j) * 4;
			memcpy(decrypted + start, &(aemProc[i][j].pid), 4);
		}
	}

	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, decrypted, AEM_LEN_MSG, encrypted, key_mng);
	send(sock, encrypted, AEM_LEN_ENCRYPTED, 0);
}

static void respond_manager(const int sock) {
	while (recv(sock, encrypted, AEM_LEN_ENCRYPTED, 0) == AEM_LEN_ENCRYPTED) {
		if (crypto_secretbox_open_easy(decrypted, encrypted + crypto_secretbox_NONCEBYTES, AEM_LEN_ENCRYPTED - crypto_secretbox_NONCEBYTES, encrypted, key_mng) != 0) return;

		switch(decrypted[0]) {
			case '\0': break; // No action, only requesting info

			case 'T': { // Request termination
				uint32_t pid;
				memcpy(&pid, decrypted + 2, 4);
				process_kill(decrypted[1], pid, SIGUSR1);
				break;
			}

			case 'K': { // Request immediate termination (kill)
				uint32_t pid;
				memcpy(&pid, decrypted + 2, 4);
				process_kill(decrypted[1], pid, SIGUSR2);
				break;
			}

			case 'S': { // Spawn
				process_spawn(decrypted[1]);
				break;
			}

			default: return; // Invalid command
		}

		cryptSend(sock);
	}
}

__attribute__((warn_unused_result))
static int initSocket(const int * const sock, const int port) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int ret = bind(*sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(*sock, 3); // socket, backlog (# of connections to keep in queue)
	return 0;
}

static void setSocketTimeout(const int sock) {
	struct timeval tv;
	tv.tv_sec = AEM_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

int receiveConnections(void) {
	setAccessKeys();
	process_spawn(AEM_PROCESSTYPE_ACCOUNT);
	process_spawn(AEM_PROCESSTYPE_STORAGE);
	process_spawn(AEM_PROCESSTYPE_ENQUIRY);

	sockMain = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sockMain < 0) {wipeKeys(); return EXIT_FAILURE;}

	if (initSocket(&sockMain, AEM_PORT_MANAGER) != 0) {wipeKeys(); return EXIT_FAILURE;}

	while (!terminate) {
		sockClient = accept4(sockMain, NULL, NULL, SOCK_CLOEXEC);
		if (sockClient < 0) break;
		setSocketTimeout(sockClient);
		respond_manager(sockClient);
		close(sockClient);
	}

	close(sockMain);
	wipeKeys();
	return EXIT_SUCCESS;
}
