#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "IO.h"

#include "../Data/internal.h"
#include "../Global.h"

#include "ClientHandler.h"

#define AEM_SOCKPATH AEM_SOCKPATH_STORAGE
#include "../Common/tier2_common.c"

static bool terminate = false;

void tc_term(void) {
	terminate = true;
}

void takeConnections(void) {
	const int sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) return;
	listen(sockListen, 50);

	while (!terminate) {
		const int sock = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sock < 0) continue;

		if (!peerOk(sock)) {
			syslog(LOG_WARNING, "Connection rejected from invalid user");
			close(sock);
			continue;
		}

		unsigned char enc[crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 65];
		const ssize_t lenEnc = recv(sock, enc, crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 65, 0);
		if (lenEnc < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 2) {close(sock); continue;}
		const size_t lenClr = lenEnc - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES - 1;

		unsigned char clr[lenClr];
		if (enc[0] == 'A' && crypto_secretbox_open_easy(clr, enc + 1 + crypto_secretbox_NONCEBYTES, lenClr + crypto_secretbox_MACBYTES, enc + 1, AEM_KEY_ACCESS_STORAGE_API) == 0) {
			switch (clr[0]) {
				case AEM_API_INTERNAL_ERASE: {
					if (lenClr != crypto_box_PUBLICKEYBYTES + 1) break;
					if (send(sock, (unsigned char[]){(storage_erase(clr + 1) == 0) ? AEM_INTERNAL_RESPONSE_OK : AEM_INTERNAL_RESPONSE_ERR}, 1, 0) != 1) syslog(LOG_ERR, "Failed send");
				break;}

				case AEM_API_MESSAGE_BROWSE: {
					if (lenClr != 1 + crypto_box_PUBLICKEYBYTES && lenClr != 1 + crypto_box_PUBLICKEYBYTES + 17) {syslog(LOG_ERR, "Message/Browse: Wrong length: %ld", lenClr); break;}

					unsigned char *msgData = NULL;
					const int sz = storage_read(clr + 1, (lenClr == 1 + crypto_box_PUBLICKEYBYTES + 17) ? clr + 1 + crypto_box_PUBLICKEYBYTES : NULL, &msgData);

					if (sz == 0) {
						if (send(sock, "\0", 1, 0) != 1) syslog(LOG_ERR, "Failed send");
					} else if (msgData != NULL) {
						if (sz > 0 && send(sock, msgData, sz, 0) != sz) syslog(LOG_ERR, "Failed send");
						sodium_free(msgData);
					}
				break;}

				case AEM_API_MESSAGE_DELETE: {
					unsigned char ids[8192];

					const ssize_t lenIds = recv(sock, ids, 8192, 0);
					if (lenIds % 16 != 0) {
						syslog(LOG_ERR, "Message/Delete: Invalid data received");
						send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_ERR}, 1, 0);
						break;
					}

					unsigned char resp = AEM_INTERNAL_RESPONSE_ERR;

					for (int i = 0; i < lenIds / 16; i++) {
						if (storage_delete(clr + 1, ids + i * 16) == 0) resp = AEM_INTERNAL_RESPONSE_OK;
					}

					send(sock, (unsigned char[]){resp}, 1, 0);
				break;}

				case AEM_API_MESSAGE_UPLOAD: {
					uint16_t sze;
					memcpy(&sze, clr + 1, 2);

					unsigned char * const data = malloc((sze + AEM_MSG_MINBLOCKS) * 16);
					if (data == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

					if (recv(sock, data, (sze + AEM_MSG_MINBLOCKS) * 16, MSG_WAITALL) == (sze + AEM_MSG_MINBLOCKS) * 16) {
						storage_write(clr + 3, data, sze);
					} else syslog(LOG_ERR, "Failed receiving data from API");

					free(data);

					send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
				break;}

				default: syslog(LOG_ERR, "Invalid API command");
			}
		} else if (enc[0] == 'M' && crypto_secretbox_open_easy(clr, enc + 1 + crypto_secretbox_NONCEBYTES, lenEnc - 1 - crypto_secretbox_NONCEBYTES, enc + 1, AEM_KEY_ACCESS_STORAGE_MTA) == 0) {
			if (clr[0] == AEM_MTA_INSERT) {
				uint16_t sze;
				while(1) {
					if (recv(sock, &sze, 2, MSG_WAITALL) != 2) {syslog(LOG_ERR, "MTA unclean end"); break;}
					if (sze == 0) break;

					unsigned char * const data = malloc((sze + AEM_MSG_MINBLOCKS) * 16);
					if (data == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

					if (recv(sock, data, (sze + AEM_MSG_MINBLOCKS) * 16, MSG_WAITALL) == (sze + AEM_MSG_MINBLOCKS) * 16) {
						storage_write(clr + 1, data, sze);
					} else syslog(LOG_ERR, "Failed receiving data from MTA");

					free(data);
				}
			} else syslog(LOG_ERR, "Invalid MTA command");
		}

		close(sock);
	}

	close(sockListen);
}
