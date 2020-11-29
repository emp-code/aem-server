#include <fcntl.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/SetCaps.h"
#include "../Data/internal.h"

#include "DNS.h"

#define AEM_LOGNAME "AEM-Enq"
#define AEM_SOCK_QUEUE 50

#define AEM_MAXLEN_ENQUIRY_ENC (32 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define AEM_MINLEN_ENQUIRY_ENC (4 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)

static bool terminate = false;

static void sigTerm(const int sig) {
	if (sig == SIGUSR1) {
		terminate = true;
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

static int bindSocket(const int sock) {
	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, AEM_SOCKPATH_ENQUIRY, AEM_SOCKPATH_LEN);
	return bind(sock, (struct sockaddr*)&addr, sizeof(addr.sun_family) + AEM_SOCKPATH_LEN);
}

static bool peerOk(const int sock) {
	struct ucred peer;
	unsigned int lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.gid == getgid() && peer.uid == getuid());
}

void takeConnections(void) {
	umask(0077);

	const int sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) return;
	listen(sockListen, AEM_SOCK_QUEUE);

	while (!terminate) {
		const int sock = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sock < 0) continue;

		if (!peerOk(sock)) {
			syslog(LOG_WARNING, "Connection rejected from invalid peer");
			close(sock);
			continue;
		}

		unsigned char enc[AEM_MAXLEN_ENQUIRY_ENC];
		const ssize_t lenEnc = recv(sock, enc, AEM_MAXLEN_ENQUIRY_ENC, 0);
		if (lenEnc < AEM_MINLEN_ENQUIRY_ENC) {
			syslog(LOG_ERR, "Peer sent too little data");
			close(sock);
			continue;
		}

		const size_t lenDec = lenEnc - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
		unsigned char dec[lenDec];
		if (crypto_secretbox_open_easy(dec, enc + crypto_secretbox_NONCEBYTES, lenDec + crypto_secretbox_MACBYTES, enc, AEM_KEY_ACCESS_ENQUIRY_ALL) == 0) {
			switch (dec[0]) {
				case AEM_DNS_LOOKUP:{
					unsigned char mxDomain[256];
					int lenMxDomain = 0;
					const uint32_t ip = queryDns(dec + 1, lenDec - 1, mxDomain, &lenMxDomain);

					if (lenMxDomain > 4 && lenMxDomain < 256) {
						send(sock, &ip, 4, 0);
						send(sock, &lenMxDomain, sizeof(int), 0);
						send(sock, mxDomain, lenMxDomain, 0);
					}
				break;}

				default:
					syslog(LOG_ERR, "Invalid command: %u", dec[0]);
			}
		} else syslog(LOG_WARNING, "Failed decrypting message from peer (%zd bytes)", lenEnc);

		close(sock);
	}

	close(sockListen);
}

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

//	if (read(argv[0][0], accessKey, AEM_LEN_ACCESSKEY) != AEM_LEN_ACCESSKEY) {syslog(LOG_ERR, "Terminating: Failed loading AccessKey"); return EXIT_FAILURE;}
	close(argv[0][0]);

	if (tlsSetup() != 0) {syslog(LOG_ERR, "Terminating: Failed tlsSetup()"); return EXIT_FAILURE;}

	syslog(LOG_INFO, "Ready");
	takeConnections();
	syslog(LOG_INFO, "Terminating");

	tlsFree();
	return EXIT_SUCCESS;
}
