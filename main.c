#define _GNU_SOURCE // for accept4, memmem

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <locale.h> // for setlocale

#include <sodium.h>
#include <mbedtls/ssl.h>

#include "aem_file.h"

#include "Includes/Brotli.h"

#include "http.h"
#include "https.h"
#include "smtp.h"

#define AEM_PORT_HTTP 80
#define AEM_PORT_HTTPS 443
#define AEM_PORT_SMTP 25

#define AEM_HOMEDIR "/var/lib/allears"
#define AEM_DIRMODE (0 | S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR)

bool isGoodPerm(const unsigned int uid, const char * const path) {
	struct stat s;
	if (stat(path, &s) != 0) return false;

	return (s.st_uid == uid && s.st_gid == uid && s.st_mode == AEM_DIRMODE);
}

static int dropRoot() {
	const struct passwd * const p = getpwnam("allears");
	if (p == NULL) return -1;

	if ((int)p->pw_uid != (int)p->pw_gid) return 2;

	if (
	   strcmp(p->pw_shell, "/bin/nologin")      != 0
	&& strcmp(p->pw_shell, "/usr/bin/nologin")  != 0
	&& strcmp(p->pw_shell, "/usr/sbin/nologin") != 0
	&& strcmp(p->pw_shell, "/sbin/nologin")     != 0
	) return 3;

	if (strcmp(p->pw_dir, AEM_HOMEDIR) != 0) return 4;
	if (!isGoodPerm(p->pw_uid, AEM_HOMEDIR)) return 5;

	if (chroot(p->pw_dir) != 0) return 6;

	if (setgid(p->pw_gid) != 0) return 7;
	if (setuid(p->pw_uid) != 0) return 8;

	if (getuid() != p->pw_uid || getgid() != p->pw_gid) return 9;

	return 0;
}

// Allow restarting the server immediately after kill
static void allowQuickRestart(const int * const sock) {
	const int optval = 1;
	setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));
}

static int initSocket(const int * const sock, const int port) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	allowQuickRestart(sock);

	const int ret = bind(*sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(*sock, 10); // socket, backlog (# of connections to keep in queue)
	return 0;
}

static void receiveConnections_http(const char * const domain, const size_t lenDomain) {
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (initSocket(&sock, AEM_PORT_HTTP) != 0) {
		puts("[Main.HTTP] Failed to create HTTP socket");
		return;
	}

	const int ret = dropRoot();
	if (ret != 0) {
		printf("[Main.HTTP] dropRoot() failed: %d\n", ret);
		return;
	}

	puts("[Main.HTTP] Ready");

	while(1) {
		const int sockNew = accept4(sock, NULL, NULL, SOCK_NONBLOCK);
		respond_http(sockNew, domain, lenDomain);
	}
}

static int aem_countFiles(const char * const path, const char * const ext, const size_t extLen) {
	DIR * const dir = opendir(path);
	if (dir == NULL) return 0;

	int counter = 0;

	while(1) {
		const struct dirent * const de = readdir(dir);
		if (de == NULL) break;
		if (memcmp(de->d_name + strlen(de->d_name) - extLen, ext, extLen) == 0) counter++;
	}

	closedir(dir);
	return counter;
}

static struct aem_file *aem_loadFiles(const char * const path, const char * const ext, const size_t extLen, const int fileCount, const unsigned char * const spk) {
	if (path == NULL || ext == NULL || extLen < 1 || fileCount < 1) return NULL;

	DIR * const dir = opendir(path);
	if (dir == NULL) return NULL;

	struct aem_file * const f = sodium_allocarray(fileCount, sizeof(struct aem_file));
	if (f == NULL) return NULL;

	for (int counter = 0; counter < fileCount;) {
		const struct dirent * const de = readdir(dir);
		if (de == NULL) {f[counter].lenData = 0; break;}

		if (memcmp(de->d_name + strlen(de->d_name) - extLen, ext, extLen) == 0) {
			char filePath[strlen(path) + strlen(de->d_name) + 1];
			sprintf(filePath, "%s/%s", path, de->d_name);

			const int fd = open(filePath, O_RDONLY);
			if (fd < 0) {f[counter].lenData = 0; continue;}
			const off_t bytes = lseek(fd, 0, SEEK_END);

			if (strcmp(ext, ".css") == 0 || strcmp(ext, ".html") == 0 || strcmp(ext, ".js") == 0) {
				// Files to be compressed
				char *tempData = malloc(bytes);
				if (tempData == NULL) {printf("[Main.HTTPS] Failed to allocate memory for loading %s. Quitting.\n", de->d_name); break;}

				const ssize_t readBytes = pread(fd, tempData, bytes, 0);
				close(fd);

				if (readBytes == bytes) {
					while (spk != NULL) {
						char * const spk_loc = memmem(tempData, bytes, "_PLACEHOLDER_FOR_ALL-EARS_MAIL_SERVER_PUBLIC_KEY_DO_NOT_MODIFY._", 64);
						if (spk_loc == NULL) break;
						char hex[65];
						sodium_bin2hex(hex, 65, spk, crypto_box_PUBLICKEYBYTES);
						memcpy(spk_loc, hex, 64);
					}

					brotliCompress(&tempData, (size_t*)&bytes);

					f[counter].filename = strdup(de->d_name);
					f[counter].lenData = bytes;

					f[counter].data = sodium_malloc(bytes);
					if (f[counter].data == NULL) {printf("[Main.HTTPS] Failed to allocate memory (Sodium) for loading %s. Quitting.\n", de->d_name); break;}
					memcpy(f[counter].data, tempData, bytes);
					sodium_mprotect_readonly(f[counter].data);
					free(tempData);

					printf("[Main.HTTPS] Loaded %s (%zd bytes compressed)\n", f[counter].filename, f[counter].lenData);
				} else {
					printf("[Main.HTTPS] Failed to load %s\n", de->d_name);
					free(tempData);
				}
			} else {
				// Files not to be compressed
				f[counter].data = sodium_malloc(bytes);
				if (f[counter].data == NULL) {printf("[Main.HTTPS] Failed to allocate memory (Sodium) for loading %s. Quitting.\n", de->d_name); break;}

				const ssize_t readBytes = pread(fd, f[counter].data, bytes, 0);
				close(fd);

				if (readBytes == bytes) {
					sodium_mprotect_readonly(f[counter].data);

					f[counter].lenData = bytes;
					f[counter].filename = strdup(de->d_name);

					printf("[Main.HTTPS] Loaded %s (%zd bytes)\n", f[counter].filename, f[counter].lenData);
				} else {
					printf("[Main.HTTPS] Failed to load %s\n", de->d_name);
					sodium_free(f[counter].data);
				}
			}

			counter++;
		}
	}

	sodium_mprotect_readonly(f);
	closedir(dir);
	return f;
}

static int loadTlsCert(mbedtls_x509_crt * const cert) {
	mbedtls_x509_crt_init(cert);
	const int ret = mbedtls_x509_crt_parse_file(cert, "AllEars/TLS.crt");
	if (ret == 0) return 0;

	printf("[Main.Cert] mbedtls_x509_crt_parse returned %d\n", ret);
	return 1;
}

static int loadTlsKey(mbedtls_pk_context * const key) {
	mbedtls_pk_init(key);
	const int ret = mbedtls_pk_parse_keyfile(key, "AllEars/TLS.key", NULL);
	if (ret == 0) return 0;

	printf("[Main.Cert] mbedtls_pk_parse_key returned %d\n", ret);
	return 1;
}

static int loadAddrKey(unsigned char * const addrKey) {
	const int fd = open("AllEars/Address.key", O_RDONLY);
	if (fd < 0 || lseek(fd, 0, SEEK_END) != crypto_pwhash_SALTBYTES) return 1;

	const off_t readBytes = pread(fd, addrKey, crypto_pwhash_SALTBYTES, 0);
	close(fd);
	if (readBytes == crypto_pwhash_SALTBYTES) return 0;

	printf("[Main.AddrKey] pread returned: %ld\n", readBytes);
	return 1;
}

static int receiveConnections_https(const char * const domain, const size_t lenDomain) {
	if (access("html/index.html", R_OK) == -1 ) {
		puts("[Main.HTTPS] Terminating: missing html/index.html");
		return 1;
	}

	mbedtls_x509_crt tlsCert;
	if (loadTlsCert(&tlsCert) < 0) return 1;

	mbedtls_pk_context tlsKey;
	if (loadTlsKey(&tlsKey) < 0) return 1;

	unsigned char addrKey[crypto_pwhash_SALTBYTES];
	int ret = loadAddrKey(addrKey);
	if (ret < 0) {
		puts("[Main.HTTPS] Terminating: failed to load address key");
		return 1;
	}

	const int numCss  = aem_countFiles("css",  ".css",  4);
	const int numHtml = aem_countFiles("html", ".html", 5);
	const int numImg  = aem_countFiles("img",  ".webp", 5);
	const int numJs   = aem_countFiles("js",   ".js",   3);

	printf("[Main.HTTPS] Loading files: %d CSS, %d HTML, %d image, %d Javascript\n", numCss, numHtml, numImg, numJs);

	// Keys for web API
	unsigned char * const spk = malloc(crypto_box_PUBLICKEYBYTES);
	if (spk == NULL) return 1;
	unsigned char * const ssk = sodium_malloc(crypto_box_SECRETKEYBYTES);
	if (ssk == NULL) {free(spk); return 1;}
	crypto_box_keypair(spk, ssk);
	sodium_mprotect_readonly(ssk);

	struct aem_file * const fileCss  = aem_loadFiles("css",  ".css",  4, numCss, NULL);
	struct aem_file * const fileHtml = aem_loadFiles("html", ".html", 5, numHtml, NULL);
	struct aem_file * const fileImg  = aem_loadFiles("img",  ".webp", 5, numImg, NULL);
	struct aem_file * const fileJs   = aem_loadFiles("js",   ".js",   3, numJs, spk);
	free(spk);

	struct aem_fileSet * const fileSet = sodium_malloc(sizeof(struct aem_fileSet));
	if (fileSet == NULL) {puts("[Main.HTTPS] Failed to allocate memory for fileSet"); return 1;}
	fileSet->cssFiles  = fileCss;
	fileSet->htmlFiles = fileHtml;
	fileSet->imgFiles  = fileImg;
	fileSet->jsFiles   = fileJs;
	fileSet->cssCount  = numCss;
	fileSet->htmlCount = numHtml;
	fileSet->imgCount  = numImg;
	fileSet->jsCount   = numJs;
	sodium_mprotect_readonly(fileSet);

	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) ret = -2;
	if (ret == 0) {if (initSocket(&sock, AEM_PORT_HTTPS) != 0) ret = -3;}
	if (ret == 0) {if (dropRoot() != 0) ret = -4;}

	if (ret == 0) {
		puts("[Main.HTTPS] Ready");

		while(1) {
			const int newSock = accept(sock, NULL, NULL);
			if (newSock < 0) {puts("[Main.HTTPS] Failed to create socket for accepting connection"); break;}

			const int pid = fork();
			if (pid < 0) {puts("[Main.HTTPS] Failed fork"); break;}
			else if (pid == 0) {
				// Child goes on to communicate with the client
				respond_https(newSock, &tlsCert, &tlsKey, ssk, addrKey, domain, lenDomain, fileSet);
				close(newSock);
				break;
			} else close(newSock); // Parent closes its copy of the socket and moves on to accept a new one
		}
	}

	sodium_free(ssk);

	for (int i = 0; i < numCss;  i++) {free(fileCss[i].filename);  sodium_free(fileCss[i].data);}
	for (int i = 0; i < numHtml; i++) {free(fileHtml[i].filename); sodium_free(fileHtml[i].data);}
	for (int i = 0; i < numImg;  i++) {free(fileImg[i].filename);  sodium_free(fileImg[i].data);}
	for (int i = 0; i < numJs;   i++) {free(fileJs[i].filename);   sodium_free(fileJs[i].data);}

	sodium_free(fileCss);
	sodium_free(fileHtml);
	sodium_free(fileImg);
	sodium_free(fileJs);
	sodium_free(fileSet);

	mbedtls_x509_crt_free(&tlsCert);
	mbedtls_pk_free(&tlsKey);
	close(sock);
	return 0;
}

static int receiveConnections_smtp(const char * const domain, const size_t lenDomain) {
	mbedtls_x509_crt tlsCert;
	if (loadTlsCert(&tlsCert) < 0) return 1;

	mbedtls_pk_context tlsKey;
	if (loadTlsKey(&tlsKey) < 0) return 1;

	unsigned char addrKey[crypto_pwhash_SALTBYTES];
	int ret = loadAddrKey(addrKey);
	if (ret < 0) {
		puts("[Main.HTTPS] Terminating: failed to load address key");
		return 1;
	}

	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) ret = -2;
	if (ret == 0) {if (initSocket(&sock, AEM_PORT_SMTP) != 0) ret = -3;}
	if (ret == 0) {if (dropRoot() != 0) ret = -4;}

	if (ret == 0) {
		puts("[Main.SMTP] Ready");

		while(1) {
			struct sockaddr_in clientAddr;
			unsigned int clen = sizeof(clientAddr);
			const int newSock = accept(sock, (struct sockaddr*)&clientAddr, &clen);
			if (newSock < 0) {puts("[Main.SMTP] Failed to create socket for accepting connection"); break;}

			const int pid = fork();
			if (pid < 0) {puts("[Main.SMTP] Failed fork"); break;}
			else if (pid == 0) {
				// Child goes on to communicate with the client
				respond_smtp(newSock, &tlsCert, &tlsKey, addrKey, domain, lenDomain, &clientAddr);
				close(newSock);
				break;
			} else close(newSock); // Parent closes its copy of the socket and moves on to accept a new one
		}
	}

	mbedtls_x509_crt_free(&tlsCert);
	mbedtls_pk_free(&tlsKey);
	close(sock);
	return 0;
}

char *getDomainInfo(mbedtls_x509_crt * const cert) {
	char certInfo[1000];
	mbedtls_x509_crt_info(certInfo, 1000, "AEM_", cert);

	char *c = strstr(certInfo, "\nAEM_subject name");
	if (c == NULL) return NULL;
	c += 17;

	char * const end = strchr(c, '\n');
	*end = '\0';

	c = strstr(c, ": CN=");
	if (c == NULL) return NULL;
	return strdup(c + 5);
}

size_t getDomainLenFromCert(mbedtls_x509_crt * const cert) {
	char * const c = getDomainInfo(cert);
	if (c == NULL) return 0;
	const size_t s = strlen(c);
	free(c);
	return s;
}

int getDomainFromCert(char * const dom, const size_t len, mbedtls_x509_crt * const cert) {
	char * const c = getDomainInfo(cert);
	if (c == NULL) return -1;
	memcpy(dom, c, len);
	free(c);
	return 0;
}

int main() {
	if (getuid() != 0) {
		puts("[Main] Terminating: All-Ears must be started as root");
		return EXIT_FAILURE;
	}

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {puts("[Main] Terminating: signal failed"); return EXIT_FAILURE;} // Prevent zombie processes
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {puts("[Main] Terminating: signal failed"); return EXIT_FAILURE;} // Prevent writing to closed/invalid sockets from ending the process

	puts("[Main] All-Ears Mail");

	if (sodium_init() < 0) {
		puts("[Main] Terminating: Failed to initialize libsodium");
		return EXIT_FAILURE;
	}

	setlocale(LC_ALL, "C");

	// Get domain from TLS certificate
	mbedtls_x509_crt cert;
	mbedtls_x509_crt_init(&cert);
	int ret = mbedtls_x509_crt_parse_file(&cert, "AllEars/TLS.crt");
	if (ret != 0) {
		printf("[Main] Terminating: mbedtls_x509_crt_parse returned %d\n", ret);
		return EXIT_FAILURE;
	}

	const size_t lenDomain = getDomainLenFromCert(&cert);
	char domain[lenDomain];
	ret = getDomainFromCert(domain, lenDomain, &cert);
	mbedtls_x509_crt_free(&cert);
	if (ret != 0) {puts("[Main] Terminating: Failed to get domain from certificate"); return EXIT_FAILURE;}

	printf("[Main] Domain detected as '%.*s'\n", (int)lenDomain, domain);

	// Start server processes
	int pid = fork();
	if (pid < 0) return EXIT_FAILURE;
	if (pid == 0) return receiveConnections_https(domain, lenDomain);

	pid = fork();
	if (pid < 0) return EXIT_FAILURE;
	if (pid == 0) return receiveConnections_smtp(domain, lenDomain);

	receiveConnections_http(domain, lenDomain);

	return EXIT_SUCCESS;
}
