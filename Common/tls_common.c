#include <syslog.h>

#include "tls_common.h"

void sendData(mbedtls_ssl_context * const ssl, const void * const data, const size_t lenData) {
	if (data == NULL || lenData < 1) return;

	size_t sent = 0;

	while (sent < lenData) {
		int ret;
		do {ret = mbedtls_ssl_write(ssl, (const unsigned char*)data + sent, lenData - sent);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
		if (ret < 0) {syslog(LOG_NOTICE, "mbedtls_ssl_write failed: %x\n", -ret); return;}
		sent += ret;
	}
}
