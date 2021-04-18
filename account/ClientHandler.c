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

#define AEM_SOCKPATH AEM_SOCKPATH_ACCOUNT
#include "../Common/ClientHandler_common.c"

void takeConnections(void) {
	const int sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) return;
	listen(sockListen, 50);

	while (!terminate) {
		const int sockClient = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sockClient < 0) continue;

		if (!peerOk(sockClient)) {
			syslog(LOG_WARNING, "Connection rejected from invalid user");
			close(sockClient);
			continue;
		}

		const size_t encLen = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 2 + crypto_box_PUBLICKEYBYTES;
		unsigned char enc[encLen];

		ssize_t reqLen = recv(sockClient, enc, encLen, 0);
		if (reqLen <= crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
			syslog(LOG_WARNING, "Invalid connection");
			close(sockClient);
			continue;
		}

		reqLen -= (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 1);
		unsigned char req[reqLen];

		if (enc[0] == 'A' && reqLen == 1 + crypto_box_PUBLICKEYBYTES && crypto_secretbox_open_easy(req, enc + 1 + crypto_secretbox_NONCEBYTES, 1 + crypto_box_PUBLICKEYBYTES + crypto_secretbox_MACBYTES, enc + 1, AEM_KEY_ACCESS_ACCOUNT_API) == 0) {
			const int num = userNumFromPubkey(req + 1);
			if (num < 0) {
				send(sockClient, (unsigned char[]){AEM_INTERNAL_RESPONSE_NOTEXIST}, 1, 0);
				close(sockClient);
				continue;
			}

			switch (req[0]) {
				case AEM_API_ACCOUNT_BROWSE: api_account_browse(sockClient, num); break;
				case AEM_API_ACCOUNT_CREATE: api_account_create(sockClient, num); break;
				case AEM_API_ACCOUNT_DELETE: api_account_delete(sockClient, num); break;
				case AEM_API_ACCOUNT_UPDATE: api_account_update(sockClient, num); break;

				case AEM_API_ADDRESS_CREATE: api_address_create(sockClient, num); break;
				case AEM_API_ADDRESS_DELETE: api_address_delete(sockClient, num); break;
				case AEM_API_ADDRESS_UPDATE: api_address_update(sockClient, num); break;

				case AEM_API_MESSAGE_SENDER: api_message_sender(sockClient, num); break;
				case AEM_API_PRIVATE_UPDATE: api_private_update(sockClient, num); break;
				case AEM_API_SETTING_LIMITS: api_setting_limits(sockClient, num); break;

				// Internal functions
				case AEM_API_INTERNAL_ADRPK: api_internal_adrpk(sockClient, num); break;
				case AEM_API_INTERNAL_EXIST: send(sockClient, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0); break; // existence verified by userNumFromPubkey()
				case AEM_API_INTERNAL_LEVEL: api_internal_level(sockClient, num); break;
				case AEM_API_INTERNAL_MYADR: api_internal_myadr(sockClient, num); break;
				case AEM_API_INTERNAL_UINFO: api_internal_uinfo(sockClient, num); break;
				case AEM_API_INTERNAL_PUBKS: api_internal_pubks(sockClient, num); break;

				//default: // Invalid
			}

			close(sockClient);
			continue;
		} else if (enc[0] == 'M' && reqLen == 11 && crypto_secretbox_open_easy(req, enc + 1 + crypto_secretbox_NONCEBYTES, 11 + crypto_secretbox_MACBYTES, enc + 1, AEM_KEY_ACCESS_ACCOUNT_MTA) == 0) {
			switch(req[0]) {
				case AEM_MTA_ADREXISTS_SHIELD: mta_shieldExist(sockClient, req + 1); break;
				case AEM_MTA_GETPUBKEY_NORMAL: mta_getPubKey(sockClient, req + 1, false); break;
				case AEM_MTA_GETPUBKEY_SHIELD: mta_getPubKey(sockClient, req + 1, true);  break;
			}

			close(sockClient);
			continue;
		}

		close(sockClient);
		syslog(LOG_WARNING, "Invalid request");
	}

	close(sockListen);
	return;
}
