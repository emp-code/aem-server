#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Config.h"

#include "DNS_protocol.h"

#include "DNS.h"

#define AEM_DNS_BUFLEN 512

static int connectSocket(void) {
	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {syslog(LOG_ERR, "Failed socket(): %m"); return -1;}

	struct sockaddr_in myaddr;
	myaddr.sin_family = AF_INET;
	myaddr.sin_port = htons(AEM_DNS_SERVER_PORT);
	inet_aton(AEM_DNS_SERVER_ADDR, &myaddr.sin_addr);

	if (connect(sock, &myaddr, sizeof(struct sockaddr_in)) != 0) {
		syslog(LOG_ERR, "Failed connect(): %m");
		close(sock);
		return -1;
	}

	return sock;
}

static bool checkDnsLength(const unsigned char * const src, const int len) {
	if (len < 1) return false;

	uint16_t u;
	memcpy((unsigned char*)&u + 0, src + 1, 1);
	memcpy((unsigned char*)&u + 1, src + 0, 1);

	if (len != (int)u + 2) {
		syslog(LOG_INFO, "DNS length mismatch: %d/%u", len, u + 2);
		return false;
	}

	return true;
}

uint32_t queryDns_a(const unsigned char * const domain, const size_t lenDomain) {
	if (domain == NULL || domain[0] == '\0' || lenDomain < 4) return 0; // a.bc

	uint16_t reqId;
	randombytes_buf(&reqId, 2);

	unsigned char req[100];
	bzero(req, 100);

	int reqLen = dnsCreateRequest(reqId, req, domain, lenDomain, AEM_DNS_RECORDTYPE_A);

	const int sock = connectSocket();
	if (sock < 0) return 0;

	int ret = send(sock, req, reqLen, 0);

	unsigned char res[AEM_DNS_BUFLEN];
	ret = recv(sock, res, AEM_DNS_BUFLEN, 0);
	close(sock);
	if (!checkDnsLength(res, ret)) return 0;

	const uint32_t ip = dnsResponse_GetIp(reqId, res + 2, ret - 2, domain, lenDomain, AEM_DNS_RECORDTYPE_A);
	return ip;
}

void queryDns_dkim(const unsigned char * const selector, const size_t lenSelector, const unsigned char * const domain, const size_t lenDomain, unsigned char * const dkimRecord, int * const lenDkimRecord) {
	if (domain == NULL || lenDomain < 1 || domain[0] == '\0' || selector == NULL || lenSelector < 1 || selector[0] == '\0') return;

	uint16_t reqId;
	randombytes_buf(&reqId, 2);

	unsigned char req[100];
	bzero(req, 100);

	size_t lenDkimDomain = lenSelector + 12 + lenDomain;
	unsigned char dkimDomain[lenDkimDomain];
	memcpy(dkimDomain, selector, lenSelector);
	memcpy(dkimDomain + lenSelector, "._domainkey.", 12);
	memcpy(dkimDomain + lenSelector + 12, domain, lenDomain);

	int reqLen = dnsCreateRequest(reqId, req, dkimDomain, lenDkimDomain, AEM_DNS_RECORDTYPE_TXT);

	const int sock = connectSocket();
	if (sock < 0) return;

	int ret = send(sock, req, reqLen, 0);

	unsigned char res[1024];
	ret = recv(sock, res, 1024, 0);
	close(sock);
	if (!checkDnsLength(res, ret)) return;

	dnsResponse_GetNameRecord(reqId, res + 2, ret - 2, dkimDomain, lenDkimDomain, dkimRecord, lenDkimRecord, AEM_DNS_RECORDTYPE_TXT);
}

uint32_t queryDns(const unsigned char * const domain, const size_t lenDomain, unsigned char * const mxDomain, int * const lenMxDomain) {
	if (domain == NULL || domain[0] == '\0' || lenDomain < 4 || mxDomain == NULL || lenMxDomain == NULL) return 0; // a.bc
	*lenMxDomain = 0;

	uint16_t reqId;
	randombytes_buf(&reqId, 2);

	unsigned char req[100];
	bzero(req, 100);

	int reqLen = dnsCreateRequest(reqId, req, domain, lenDomain, AEM_DNS_RECORDTYPE_MX);

	const int sock = connectSocket();
	if (sock < 0) return 0;

	int ret = send(sock, req, reqLen, 0);

	unsigned char res[AEM_DNS_BUFLEN];
	ret = recv(sock, res, AEM_DNS_BUFLEN, 0);
	if (!checkDnsLength(res, ret)) {close(sock); return 0;}

	uint32_t ip = 0;
	if (dnsResponse_GetNameRecord(reqId, res + 2, ret - 2, domain, lenDomain, mxDomain, lenMxDomain, AEM_DNS_RECORDTYPE_MX) == 0 && *lenMxDomain > 4) { // a.bc
		randombytes_buf(&reqId, 2);
		bzero(req, 100);
		reqLen = dnsCreateRequest(reqId, req, mxDomain, *lenMxDomain, AEM_DNS_RECORDTYPE_A);

		ret = send(sock, req, reqLen, 0);
		ret = recv(sock, res, AEM_DNS_BUFLEN, 0);
		if (!checkDnsLength(res, ret)) {close(sock); return 0;}

		ip = dnsResponse_GetIp(reqId, res + 2, ret - 2, mxDomain, *lenMxDomain, AEM_DNS_RECORDTYPE_A);
	}

	close(sock);
	return ip;
}

int getPtr(const uint32_t ip, unsigned char * const ptr, int * const lenPtr) {
	if (ip == 0 || ptr == NULL || lenPtr == NULL) return -1;

	uint16_t reqId;
	randombytes_buf(&reqId, 2);

	unsigned char req[100];
	bzero(req, 100);

	unsigned char reqDomain[100];
	sprintf((char*)reqDomain, "%u.%u.%u.%u.in-addr.arpa", ((uint8_t*)&ip)[3], ((uint8_t*)&ip)[2], ((uint8_t*)&ip)[1], ((uint8_t*)&ip)[0]);
	const size_t lenReqDomain = strlen((char*)reqDomain);

	int reqLen = dnsCreateRequest(reqId, req, reqDomain, lenReqDomain, AEM_DNS_RECORDTYPE_PTR);

	const int sock = connectSocket();
	if (sock < 0) return 0;

	int ret = send(sock, req, reqLen, 0);

	unsigned char res[AEM_DNS_BUFLEN];
	ret = recv(sock, res, AEM_DNS_BUFLEN, 0);
	close(sock);
	if (!checkDnsLength(res, ret)) return -1;

	return dnsResponse_GetNameRecord(reqId, res + 2, ret - 2, reqDomain, lenReqDomain, ptr, lenPtr, AEM_DNS_RECORDTYPE_PTR);
}
