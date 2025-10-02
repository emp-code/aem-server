#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_PEEROK_CLIENT
#include "peerok.h"

#include "Client.h"

static pid_t intcom_pids[AEM_INTCOM_SERVER_COUNT];

static unsigned char intcom_keys[AEM_INTCOM_SERVER_COUNT][crypto_aead_aegis256_KEYBYTES]; // The client's keys for each server

void intcom_setKeys_client(const unsigned char newKeys[AEM_INTCOM_SERVER_COUNT][crypto_aead_aegis256_KEYBYTES]) {
	memcpy(intcom_keys, newKeys, AEM_INTCOM_SERVER_COUNT * crypto_aead_aegis256_KEYBYTES);
}

#if defined(AEM_API) || defined(AEM_MTA) || defined(AEM_REG)
void setAccountPid(const pid_t pid) {intcom_pids[AEM_INTCOM_SERVER_ACC] = pid;}
#endif
#if defined(AEM_API) || defined(AEM_DELIVER)
void setEnquiryPid(const pid_t pid) {intcom_pids[AEM_INTCOM_SERVER_ENQ] = pid;}
#endif
void setStoragePid(const pid_t pid) {intcom_pids[AEM_INTCOM_SERVER_STO] = pid;}

static int setSockOpts(const int sock) {
	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 1;

	const int intTrue = 1;

	return (
	   setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, &intTrue, sizeof(int)) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, &intTrue, sizeof(int)) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) == 0
	) ? 0 : -1;
}

static int intcom_socket(const aem_intcom_server_t intcom_server) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;

	switch (intcom_server) {
		case AEM_INTCOM_SERVER_ACC: memcpy(sa.sun_path, AEM_INTCOM_SOCKPATH_ACCOUNT, AEM_INTCOM_SOCKPATH_LEN); break;
		case AEM_INTCOM_SERVER_ENQ: memcpy(sa.sun_path, AEM_INTCOM_SOCKPATH_ENQUIRY, AEM_INTCOM_SOCKPATH_LEN); break;
		case AEM_INTCOM_SERVER_STO: memcpy(sa.sun_path, AEM_INTCOM_SOCKPATH_STORAGE, AEM_INTCOM_SOCKPATH_LEN); break;
		default: return -1;
	}

	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_WARNING, "Failed creating IntCom socket: %m"); return -1;}
	setSockOpts(sock);

	if (connect(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + AEM_INTCOM_SOCKPATH_LEN) != 0) {
		syslog(LOG_WARNING, "Failed connecting to IntCom socket: %m");
		close(sock);
		return -1;
	}

	if (!peerOk(sock, intcom_pids[intcom_server])) {
		syslog(LOG_WARNING, "Invalid peer on IntCom socket");
		close(sock);
		return -1;
	}

	return sock;
}

int32_t intcom(const aem_intcom_server_t intcom_server, const uint32_t operation, const unsigned char * const msg, const size_t lenMsg, unsigned char ** const out, const int32_t expectedLenOut) {
	if (intcom_server >= AEM_INTCOM_SERVER_COUNT || lenMsg > AEM_INTCOM_MAXSIZE || sodium_is_zero(intcom_keys[intcom_server], crypto_aead_aegis256_KEYBYTES)) return AEM_INTCOM_RESPONSE_ERR;
	const int sock = intcom_socket(intcom_server);
	if (sock < 0) return AEM_INTCOM_RESPONSE_ERR;

	// Create and send header
	const size_t lenEncHdr = 1 + (sizeof(uint32_t) * 2) + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char encHdr[lenEncHdr];
	encHdr[0] = 
#ifdef AEM_ACCOUNT
	AEM_INTCOM_CLIENT_ACC;
#elif defined(AEM_API)
	AEM_INTCOM_CLIENT_API;
#elif defined(AEM_MTA)
	AEM_INTCOM_CLIENT_MTA;
#elif defined(AEM_REG)
	AEM_INTCOM_CLIENT_REG;
#elif defined(AEM_DELIVER)
	AEM_INTCOM_CLIENT_DLV;
#elif defined(AEM_STORAGE)
	AEM_INTCOM_CLIENT_STO;
#else
	#error Invalid IntCom client type
#endif

	randombytes_buf(encHdr + 1, crypto_aead_aegis256_NPUBBYTES);
	const uint32_t hdr[2] = {operation, lenMsg};
	crypto_aead_aegis256_encrypt(encHdr + 1 + crypto_aead_aegis256_NPUBBYTES, NULL, (const unsigned char*)hdr, sizeof(uint32_t) * 2, NULL, 0, NULL, encHdr + 1, intcom_keys[intcom_server]);
	if (send(sock, encHdr, lenEncHdr, 0) != lenEncHdr) {syslog(LOG_ERR, "IntCom[C]: Failed sending header: %m"); close(sock); return AEM_INTCOM_RESPONSE_ERR;}

	// Create and send message
	if (lenMsg > 0) {
		const size_t lenEncMsg = lenMsg + crypto_aead_aegis256_ABYTES;
		unsigned char * const encMsg = malloc(lenEncMsg);
		if (encMsg == NULL) {close(sock); syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

		sodium_increment(encHdr + 1, crypto_aead_aegis256_NPUBBYTES);
		crypto_aead_aegis256_encrypt(encMsg, NULL, msg, lenMsg, NULL, 0, NULL, encHdr + 1, intcom_keys[intcom_server]);

		const ssize_t sentBytes = send(sock, encMsg, lenEncMsg, 0);
		free(encMsg);
		if (sentBytes != (ssize_t)lenEncMsg) {syslog(LOG_ERR, "IntCom[C]: Failed sending message: %m"); close(sock); return AEM_INTCOM_RESPONSE_ERR;}
	}

	// Receive response header
	const size_t lenRcvEnc = sizeof(int32_t) + crypto_aead_aegis256_ABYTES;
	unsigned char rcv_enc[lenRcvEnc];
	if (recv(sock, rcv_enc, lenRcvEnc, MSG_WAITALL) != lenRcvEnc) {syslog(LOG_ERR, "IntCom[C]: Failed receiving header: %m"); close(sock); return AEM_INTCOM_RESPONSE_ERR;}

	sodium_increment(encHdr + 1, crypto_aead_aegis256_NPUBBYTES);
	int32_t lenOut = AEM_INTCOM_RESPONSE_ERR;
	if (crypto_aead_aegis256_decrypt((unsigned char*)&lenOut, NULL, NULL, rcv_enc, lenRcvEnc, NULL, 0, encHdr + 1, intcom_keys[intcom_server]) != 0) {close(sock); syslog(LOG_ERR, "IntCom[C]: Failed decrypting header"); return AEM_INTCOM_RESPONSE_ERR;}

	if (out == NULL || lenOut < 1) {
		close(sock);
		return lenOut;
	}

	if (expectedLenOut != 0 && lenOut != expectedLenOut) {close(sock); syslog(LOG_WARNING, "IntCom[C]: Response does not match expected length"); return AEM_INTCOM_RESPONSE_ERR;}

	// Receive response message
	unsigned char *encOut = malloc(lenOut + crypto_aead_aegis256_ABYTES);
	if (encOut == NULL) {close(sock); syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	const ssize_t recvBytes = recv(sock, encOut, lenOut + crypto_aead_aegis256_ABYTES, MSG_WAITALL);
	if (recvBytes != (ssize_t)(lenOut + crypto_aead_aegis256_ABYTES)) {
		syslog(LOG_ERR, "IntCom[C]: Failed receiving message (%d/%d): %m", recvBytes, lenOut + crypto_aead_aegis256_ABYTES);
		close(sock);
		free(encOut);
		return AEM_INTCOM_RESPONSE_ERR;
	}
	close(sock);

	*out = malloc(lenOut);
	if (*out == NULL) {close(sock); syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	sodium_increment(encHdr + 1, crypto_aead_aegis256_NPUBBYTES);
	if (crypto_aead_aegis256_decrypt(*out, NULL, NULL, encOut, lenOut + crypto_aead_aegis256_ABYTES, NULL, 0, encHdr + 1, intcom_keys[intcom_server]) != 0) {
		free(encOut);
		free(*out);
		*out = NULL;
		return AEM_INTCOM_RESPONSE_ERR;
	}

	free(encOut);
	return lenOut;
}
