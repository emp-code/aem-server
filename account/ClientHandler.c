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

#define AEM_SOCK_MAXLEN (2 + crypto_box_PUBLICKEYBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define AEM_SOCK_MINLEN (1 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)

#include "../Common/ClientHandler_common.c"

static void conn_api(const int sock, const unsigned char * const dec, const size_t lenDec) {
	const int num = userNumFromPubkey(dec + 1);
	if (num < 0) {
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_NOTEXIST}, 1, 0);
		return;
	}

	switch (dec[0]) {
		case AEM_API_ACCOUNT_BROWSE: api_account_browse(sock, num); break;
		case AEM_API_ACCOUNT_CREATE: api_account_create(sock, num); break;
		case AEM_API_ACCOUNT_DELETE: api_account_delete(sock, num); break;
		case AEM_API_ACCOUNT_UPDATE: api_account_update(sock, num); break;

		case AEM_API_ADDRESS_CREATE: api_address_create(sock, num); break;
		case AEM_API_ADDRESS_DELETE: api_address_delete(sock, num); break;
		case AEM_API_ADDRESS_UPDATE: api_address_update(sock, num); break;

		case AEM_API_MESSAGE_SENDER: api_message_sender(sock, num); break;
		case AEM_API_PRIVATE_UPDATE: api_private_update(sock, num); break;
		case AEM_API_SETTING_LIMITS: api_setting_limits(sock, num); break;

		// Internal functions
		case AEM_API_INTERNAL_ADRPK: api_internal_adrpk(sock, num); break;
		case AEM_API_INTERNAL_EXIST: send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0); break; // existence verified by userNumFromPubkey()
		case AEM_API_INTERNAL_LEVEL: api_internal_level(sock, num); break;
		case AEM_API_INTERNAL_MYADR: api_internal_myadr(sock, num); break;
		case AEM_API_INTERNAL_UINFO: api_internal_uinfo(sock, num); break;
		case AEM_API_INTERNAL_PUBKS: api_internal_pubks(sock, num); break;
	}
}

static void conn_mta(const int sock, const unsigned char * const dec, const size_t lenDec) {
	switch(dec[0]) {
		case AEM_MTA_ADREXISTS_SHIELD: mta_shieldExist(sock, dec + 1); break;
		case AEM_MTA_GETPUBKEY_NORMAL: mta_getPubKey(sock, dec + 1, false); break;
		case AEM_MTA_GETPUBKEY_SHIELD: mta_getPubKey(sock, dec + 1, true);  break;
	}
}
