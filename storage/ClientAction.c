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
	if (dec[0] == AEM_ACC_STORAGE_LIMITS && lenDec == 5) {
		updateLimits(dec + 1);
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
	} else if (dec[0] == AEM_ACC_STORAGE_AMOUNT) {
		unsigned char *out = NULL;
		const size_t lenOut = getStorageAmounts(&out);
		if (lenOut == 0 || out == NULL) return;
		send(sock, out, lenOut, 0);
		free(out);
	} else if (dec[0] == AEM_ACC_STORAGE_LEVELS) {
		const ssize_t lenData = AEM_MAXUSERS * (crypto_box_PUBLICKEYBYTES + 1);
		unsigned char *data = malloc(lenData + 1);
		if (data == NULL) return;

		const ssize_t lenRecv = recv(sock, data, lenData + 1, 0);
		if (updateLevels(data, lenRecv) == 0) send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
		free(data);
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
		unsigned char * const data = malloc(AEM_MSG_MAXSIZE + 1);
		if (data == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

		while(1) {
			int ret = recv(sock, data, AEM_MSG_MAXSIZE + 1, MSG_WAITALL);
			char status = AEM_STORE_INERROR;

			if (ret > AEM_MSG_MINSIZE && ret % 16 == 0) {
				status = storage_write(dec + 1, data, ret / 16 - AEM_MSG_MINBLOCKS);
			} else if (ret == 1 && *data == 0xFE) { // Final End
				break;
			} else {
				syslog(LOG_ERR, "Failed receiving data from MTA (%d)", ret);
			}

			if (send(sock, &status, 1, 0) != 1) {syslog(LOG_ERR, "Failed sending data to MTA"); break;}
		}

		free(data);
	} else syslog(LOG_ERR, "Invalid MTA command");
}
