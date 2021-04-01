#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/pk.h>
#include <sodium.h>

#include "Error.h"
#include "../Common/aes.h"
#include "../Global.h"

#include "SendMail.h"

#include "../Data/dkim.h"

#define AEM_API_SMTP

static bool useTls;

static unsigned char msgId_hashKey[crypto_generichash_KEYBYTES];
static unsigned char msgId_aesKey[32];

#include "../Common/tls_setup.c"

void setMsgIdKeys(const unsigned char * const src) {
	crypto_kdf_derive_from_key(msgId_hashKey, crypto_generichash_KEYBYTES, 1, "AEM-MsId", src);
	crypto_kdf_derive_from_key(msgId_aesKey, 32, 2, "AEM-MsId", src);
}

void sm_clearKeys(void) {
	sodium_memzero(msgId_hashKey, crypto_generichash_KEYBYTES);
	sodium_memzero(msgId_aesKey, 32);
}

static int makeSocket(const uint32_t ip) {
	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {syslog(LOG_ERR, "Failed socket(): %m"); return -1;}

	struct sockaddr_in mxAddr;
	mxAddr.sin_family = AF_INET;
	mxAddr.sin_port = htons(25);
	mxAddr.sin_addr.s_addr = ip;

	if (connect(sock, (struct sockaddr*)&mxAddr, sizeof(struct sockaddr_in)) != 0) {syslog(LOG_ERR, "Failed connect(): %m"); close(sock); return -1;}

	return sock;
}

static size_t rsa_sign_b64(char * const sigB64, const unsigned char * const hash, const bool isAdmin) {
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	int ret = mbedtls_pk_parse_key(&pk, isAdmin? AEM_DKIM_ADM_DATA : AEM_DKIM_USR_DATA, isAdmin? AEM_DKIM_ADM_SIZE : AEM_DKIM_USR_SIZE, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "pk_parse failed: %x", -ret); mbedtls_pk_free(&pk); return 0;}

	// Calculate the signature of the hash
	unsigned char sig[1024];
	size_t lenSig;
	ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, crypto_hash_sha256_BYTES, sig, &lenSig, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_pk_free(&pk);
	if (ret != 0) {syslog(LOG_ERR, "pk_sign failed: %x", -ret); return 0;}

	sodium_bin2base64(sigB64, sodium_base64_ENCODED_LEN(lenSig, sodium_base64_VARIANT_ORIGINAL), sig, lenSig, sodium_base64_VARIANT_ORIGINAL);
	return sodium_base64_ENCODED_LEN(lenSig, sodium_base64_VARIANT_ORIGINAL) - 1; // Remove terminating zero-byte
}

static void genMsgId(char * const out, const uint32_t ts, const unsigned char * const upk) {
	unsigned char hash_src[36];
	memcpy(hash_src, &ts, 4); // Timestamp for uniqueness
	memcpy(hash_src + 4, upk, 32);

	unsigned char hash[48]; // 384-bit
	crypto_generichash(hash, 48, hash_src, 36, msgId_hashKey, crypto_generichash_KEYBYTES);

	struct AES_ctx aes;
	AES_init_ctx(&aes, msgId_aesKey);
	AES_ECB_encrypt(&aes, hash);
	AES_ECB_encrypt(&aes, hash + 16);
	AES_ECB_encrypt(&aes, hash + 32);
	sodium_memzero(&aes, sizeof(struct AES_ctx));

	sodium_bin2base64(out, 65, hash, 48, sodium_base64_VARIANT_URLSAFE);
}

static char *createEmail(const unsigned char * const upk, const int userLevel, const struct outEmail * const email, size_t * const lenOut) {
	unsigned char bodyHash[crypto_hash_sha256_BYTES];
	if (crypto_hash_sha256(bodyHash, (unsigned char*)email->body, email->lenBody) != 0) return NULL;

	char bodyHashB64[sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(bodyHashB64, sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL), bodyHash, crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL);

	const uint32_t ts = (uint32_t)time(NULL);

	char msgId[65];
	genMsgId(msgId, ts, upk);

	const time_t msgTime = ts - 1 - randombytes_uniform(15);
	struct tm ourTime;
	if (localtime_r(&msgTime, &ourTime) == NULL) return NULL;
	char rfctime[64];
	strftime(rfctime, 64, "%a, %d %b %Y %T %z", &ourTime); // Wed, 17 Jun 2020 08:30:21 +0000

// header-hash = SHA256(headers, crlf separated + DKIM-Signature-field with b= empty, no crlf)
	char *final = malloc(2000 + email->lenBody);
	if (final == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}
	bzero(final, 2000 + email->lenBody);

	char ref[544];
	if (strlen(email->replyId) > 5) { // a@b.cd
		sprintf(ref,
			"References: <%s>\r\n"
			"In-Reply-To: <%s>\r\n"
		, email->replyId, email->replyId);
	} else ref[0] = '\0';

	sprintf(final,
		"%s" // References + In-Reply-To
		"From: %s@"AEM_DOMAIN"\r\n"
		"Date: %s\r\n"
		"Message-ID: <%s@"AEM_DOMAIN">\r\n"
		"Subject: %s\r\n"
		"To: %s\r\n"
		"DKIM-Signature:"
			" v=1;"
			" a=rsa-sha256;" //ed25519-sha256
			" c=simple/simple;"
			" d="AEM_DOMAIN";"
			" i=%s@"AEM_DOMAIN";"
			" q=dns/txt;"
			" s=%s;"
			" t=%u;"
			" x=%u;"
			" h="
				// Headers in use
				"References:"
				"In-Reply-To:"
				"From:"
				"Date:"
				"Message-ID:"
				"Subject:"
				"To:"
				// Unused headers
				"Cc:"
				"Content-Type:"
				"Mime-Version:"
				"Reply-To:"
				"Sender;"
			" bh=%s;"
			" b="
	, ref
	, email->addrFrom
	, rfctime
	, msgId
	, email->subject
	, email->addrTo
	, email->addrFrom //i=
	, (userLevel == AEM_USERLEVEL_MAX) ? "admin" : "users"
	, ts // t=
	, ts + 86400 // x=; expire after a day
	, bodyHashB64
	);

	size_t lenFinal = strlen(final);

// EdDSA
/*
	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, headHash, 32, (userLevel == AEM_USERLEVEL_MAX) ? dkim_adm_skey : dkim_usr_skey);

	char sigB64[sodium_base64_ENCODED_LEN(crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(sigB64, sodium_base64_ENCODED_LEN(crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL), sig, crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL);
*/

// RSA

	unsigned char headHash[crypto_hash_sha256_BYTES];
	if (crypto_hash_sha256(headHash, (unsigned char*)final, lenFinal) != 0) {free(final); return NULL;}

	char hB64[sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(hB64, sodium_base64_ENCODED_LEN(crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL), headHash, crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL);

	const size_t lenSigB64 = rsa_sign_b64(final + lenFinal, headHash, (userLevel == AEM_USERLEVEL_MAX));
	if (lenSigB64 < 1) {free(final); return NULL;}
	lenFinal += lenSigB64;

	memcpy(final + lenFinal, "\r\n", 2);
	lenFinal += 2;

	const char * const dkim = memmem(final, lenFinal, "\nDKIM-Signature:", 16) + 1;
	memcpy(final + lenFinal, final, dkim - final);
	memmove(final, dkim, lenFinal);

	memcpy(final + lenFinal, "\r\n", 2);
	lenFinal += 2;

	// Copy the body, dot-stuffing as necessary
	for (size_t i = 0; i < email->lenBody; i++) {
		if (email->body[i] == '.' && final[lenFinal - 1] == '\n') {
			memcpy(final + lenFinal, "..", 2);
			lenFinal += 2;
		} else {
			final[lenFinal] = email->body[i];
			lenFinal++;
		}
	}

	memcpy(final + lenFinal, ".\r\n", 3);
	lenFinal += 3;

	*lenOut = lenFinal;
	return final;
}

static int smtp_recv(const int sock, char * const buf, const size_t len) {
	if (!useTls) return recv(sock, buf, len, 0);

	int ret;
	do {ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, len);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
	return ret;
}

static int smtp_send(const int sock, const char * const data, const size_t lenData) {
	if (!useTls) return (send(sock, data, lenData, 0) == (ssize_t)lenData) ? 0 : -1;

	size_t sent = 0;

	while (sent < lenData) {
		int ret;
		do {ret = mbedtls_ssl_write(&ssl, (const unsigned char*)(data + sent), lenData - sent);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
		if (ret < 0) return ret;

		sent += ret;
	}

	return sent;
}

static void closeTls(const int sock) {
	if (useTls) {
		mbedtls_ssl_close_notify(&ssl);
		mbedtls_ssl_session_reset(&ssl);
	}

	close(sock);
}

unsigned char sendMail(const unsigned char * const upk, const int userLevel, const struct outEmail * const email, struct outInfo * const info) {
	const int sock = makeSocket(email->ip);
	if (sock < 1) {syslog(LOG_ERR, "sendMail: Failed makeSocket()"); return AEM_API_ERR_INTERNAL;}
	useTls = false;

	const ssize_t lenGreeting = smtp_recv(sock, info->greeting, 256);
	if (lenGreeting < 6 || memcmp(info->greeting, "220 ", 4) != 0) {close(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_GREET;}
	memmove(info->greeting, info->greeting + 4, lenGreeting - 6); // Between '220 ' and '\r\n'
	info->greeting[lenGreeting - 6] = '\0';

	if (smtp_send(sock, "EHLO "AEM_DOMAIN"\r\n", 7 + AEM_DOMAIN_LEN) < 0) {close(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_EHLO;}

	char buf[513];
	bzero(buf, 513);
	ssize_t len = smtp_recv(sock, buf, 512);
	if (len < 4 || memcmp(buf, "250", 3) != 0) {close(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_EHLO;}

	if (strcasestr(buf, "STARTTLS") != NULL) {
		if (smtp_send(sock, "STARTTLS\r\n", 10) < 0) {close(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_STLS;}

		len = smtp_recv(sock, buf, 512);
		if (len < 4 || memcmp(buf, "220", 3) != 0) {close(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_STLS;}

		mbedtls_ssl_set_hostname(&ssl, email->mxDomain);
		mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

		int ret;
		while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				syslog(LOG_WARNING, "SendMail: Handshake failed: %x", -ret);
				closeTls(sock);
				return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_SHAKE;
			}
		}

		useTls = true;
		info->tls_ciphersuite = mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(&ssl));
		info->tls_version = getTlsVersion(&ssl);

//		const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
//		if (flags != 0) {syslog(LOG_ERR, "SendMail: Failed verifying cert"); closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_STLS;}

		if (smtp_send(sock, "EHLO "AEM_DOMAIN"\r\n", 7 + AEM_DOMAIN_LEN) < 0) {close(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_EHLO;}

		len = smtp_recv(sock, buf, 512);
		if (len < 4 || memcmp(buf, "250", 3) != 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_EHLO;}
	} else {
		closeTls(sock);
		return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_NOTLS;
	}

	// From
	sprintf(buf, "MAIL FROM: <%s@"AEM_DOMAIN">\r\n", email->addrFrom);
	if (smtp_send(sock, buf, strlen(buf)) < 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_MAIL;}
	len = smtp_recv(sock, buf, 512);
	if (len < 4 || memcmp(buf, "250 ", 4) != 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_MAIL;}

	// To
	sprintf(buf, "RCPT TO: <%s>\r\n", email->addrTo);
	if (smtp_send(sock, buf, strlen(buf)) < 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_RCPT;}
	len = smtp_recv(sock, buf, 512);
	if (len < 4 || memcmp(buf, "250 ", 4) != 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_RCPT;}

	// Data
	if (smtp_send(sock, "DATA\r\n", 6) < 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_DATA;}
	len = smtp_recv(sock, buf, 512);
	if (len < 4 || memcmp(buf, "354 ", 4) != 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_DATA;}

	size_t lenMsg = 0;
	char * const msg = createEmail(upk, userLevel, email, &lenMsg);
	if (msg == NULL) {closeTls(sock); return AEM_API_ERR_INTERNAL;}
	if (smtp_send(sock, msg, lenMsg) < 0) {free(msg); closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_BODY;}
	free(msg);

	len = smtp_recv(sock, buf, 512);
	if (len < 4 || memcmp(buf, "250 ", 4) != 0) {closeTls(sock); return AEM_API_ERR_MESSAGE_CREATE_SENDMAIL_BODY;}

	// Quit
	if (smtp_send(sock, "QUIT\r\n", 6) < 0) smtp_recv(sock, buf, 512);
	closeTls(sock);
	return 0;
}
