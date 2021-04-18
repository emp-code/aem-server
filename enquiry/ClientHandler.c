#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/ValidDomain.h"
#include "../Common/ValidIp.h"
#include "../Data/domain.h"
#include "../Data/internal.h"
#include "../Global.h"

#include "Geo.h"
#include "DNS.h"

#include "ClientHandler.h"

#define AEM_SOCKPATH AEM_SOCKPATH_ENQUIRY
#define AEM_SOCK_QUEUE 50
#define AEM_MAXLEN_ENQUIRY_ENC (65 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define AEM_MINLEN_ENQUIRY_ENC (5 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)

#include "../Common/ClientHandler_common.c"

void takeConnections(void) {
	const int sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) return;
	listen(sockListen, 50);

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

		const size_t lenDec = lenEnc - 1 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
		unsigned char dec[lenDec];
		if (enc[0] == 'A' && crypto_secretbox_open_easy(dec, enc + 1 + crypto_secretbox_NONCEBYTES, lenDec + crypto_secretbox_MACBYTES, enc + 1, AEM_KEY_ACCESS_ENQUIRY_API) == 0) {
			switch (dec[0]) {
				case AEM_ENQUIRY_MX: {
					if (!isValidDomain((char*)dec + 1, lenDec - 1)) break;
					if (lenDec - 1 == AEM_DOMAIN_LEN && memcmp(dec + 1, AEM_DOMAIN, AEM_DOMAIN_LEN) == 0) break;

					unsigned char mxDomain[256];
					int lenMxDomain = 0;
					const uint32_t ip = queryDns(dec + 1, lenDec - 1, mxDomain, &lenMxDomain);

					if (lenMxDomain > 4 && lenMxDomain < 256) {
						send(sock, &ip, 4, 0);
						send(sock, &lenMxDomain, sizeof(int), 0);
						send(sock, mxDomain, lenMxDomain, 0);
					}
				break;}

				default: syslog(LOG_ERR, "Invalid command: %u", dec[0]);
			}
		} else if (enc[0] == 'M' && crypto_secretbox_open_easy(dec, enc + 1 + crypto_secretbox_NONCEBYTES, lenDec + crypto_secretbox_MACBYTES, enc + 1, AEM_KEY_ACCESS_ENQUIRY_MTA) == 0) {
			switch (dec[0]) {
				case AEM_ENQUIRY_IP: {
					if (lenDec != 5) break;
					const uint32_t ip = *((uint32_t*)(dec + 1));
					if (validIp(ip) == 1) break;

					unsigned char resp[129];
					const uint16_t cc = getCountryCode(ip);
					memcpy(resp, &cc, 2);

					int lenPtr = 0;
					getPtr(ip, resp + 2, &lenPtr);

					send(sock, &resp, (lenPtr < 1) ? 2 : 2 + lenPtr, 0);
				break;}

				case AEM_ENQUIRY_A: {
					if (!isValidDomain((char*)dec + 1, lenDec - 1)) break;

					const uint32_t ip = queryDns_a(dec + 1, lenDec - 1);
					send(sock, &ip, 4, 0);
				break;}

				case AEM_ENQUIRY_DKIM: {
					const unsigned char * const slash = memchr(dec + 1, '/', lenDec - 1);
					if (slash == NULL) break;

					unsigned char dkimRecord[1024];
					int lenDkimRecord = 0;

					queryDns_dkim(dec + 1, slash - (dec + 1), slash + 1, (dec + lenDec) - (slash + 1), dkimRecord, &lenDkimRecord);
					if (lenDkimRecord > 0) send(sock, dkimRecord, lenDkimRecord, 0);
				break;}

				default: syslog(LOG_ERR, "Invalid command: %u", dec[0]);
			}
		} else syslog(LOG_WARNING, "Failed decrypting message from peer (%zd bytes)", lenEnc);

		close(sock);
	}

	close(sockListen);
}
