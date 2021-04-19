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

#include "ClientAction.h"

void conn_acc(const int sock, const unsigned char * const dec, const size_t lenDec) {
	if (dec[0] == AEM_ACC_SETTING_LIMITS && lenDec == 5) {
		updateLimits(dec + 1);
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
	} else if (dec[0] == AEM_ACC_STORAGE_AMOUNT) {
		// TODO
	}
}

void conn_api(const int sock, const unsigned char * const dec, const size_t lenDec) {
	switch (dec[0]) {
		case AEM_API_INTERNAL_ERASE: {
			if (lenDec != crypto_box_PUBLICKEYBYTES + 1) return;

			if (send(sock, (unsigned char[]){(storage_erase(dec + 1) == 0) ? AEM_INTERNAL_RESPONSE_OK : AEM_INTERNAL_RESPONSE_ERR}, 1, 0) != 1) syslog(LOG_ERR, "Failed send");
		break;}

		case AEM_API_MESSAGE_BROWSE: {
			if (lenDec != 1 + crypto_box_PUBLICKEYBYTES && lenDec != 1 + crypto_box_PUBLICKEYBYTES + 17) return;

			unsigned char *msgData = NULL;
			const int sz = storage_read(dec + 1, (lenDec == 1 + crypto_box_PUBLICKEYBYTES + 17) ? dec + 1 + crypto_box_PUBLICKEYBYTES : NULL, &msgData);

			if (sz == 0) {
				if (send(sock, "\0", 1, 0) != 1) syslog(LOG_ERR, "Failed send");
			} else if (msgData != NULL) {
				if (sz > 0 && send(sock, msgData, sz, 0) != sz) syslog(LOG_ERR, "Failed send");
				sodium_free(msgData);
			}
		break;}

		case AEM_API_MESSAGE_DELETE: {
			if (lenDec != 1 + crypto_box_PUBLICKEYBYTES) return;

			unsigned char ids[8192];

			const ssize_t lenIds = recv(sock, ids, 8192, 0);
			if (lenIds % 16 != 0) {
				syslog(LOG_ERR, "Message/Delete: Invalid data received");
				send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_ERR}, 1, 0);
				break;
			}

			unsigned char resp = AEM_INTERNAL_RESPONSE_ERR;

			for (int i = 0; i < lenIds / 16; i++) {
				if (storage_delete(dec + 1, ids + i * 16) == 0) resp = AEM_INTERNAL_RESPONSE_OK;
			}

			send(sock, (unsigned char[]){resp}, 1, 0);
		break;}

		case AEM_API_MESSAGE_UPLOAD: {
			if (lenDec != 3 + crypto_box_PUBLICKEYBYTES) return;

			uint16_t sze;
			memcpy(&sze, dec + 1, 2);

			unsigned char * const data = malloc((sze + AEM_MSG_MINBLOCKS) * 16);
			if (data == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

			if (recv(sock, data, (sze + AEM_MSG_MINBLOCKS) * 16, MSG_WAITALL) == (sze + AEM_MSG_MINBLOCKS) * 16) {
				storage_write(dec + 3, data, sze);
			} else syslog(LOG_ERR, "Failed receiving data from API");

			free(data);

			send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
		break;}

		default: syslog(LOG_ERR, "Invalid API command");
	}
}

void conn_mta(const int sock, const unsigned char * const dec, const size_t lenDec) {
	if (lenDec != 1 + crypto_box_PUBLICKEYBYTES) return;

	if (dec[0] == AEM_MTA_INSERT) {
		uint16_t sze;
		while(1) {
			if (recv(sock, &sze, 2, MSG_WAITALL) != 2) {syslog(LOG_ERR, "MTA unclean end"); break;}
			if (sze == 0) break;

			unsigned char * const data = malloc((sze + AEM_MSG_MINBLOCKS) * 16);
			if (data == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

			if (recv(sock, data, (sze + AEM_MSG_MINBLOCKS) * 16, MSG_WAITALL) == (sze + AEM_MSG_MINBLOCKS) * 16) {
				storage_write(dec + 1, data, sze);
			} else syslog(LOG_ERR, "Failed receiving data from MTA");

			free(data);
		}
	} else syslog(LOG_ERR, "Invalid MTA command");
}
