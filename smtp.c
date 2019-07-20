#define AEM_SMTP_MAXSIZE_FROM 99
#define AEM_SMTP_MAXSIZE_TO   99

#define AEM_SMTP_SIZE_BUF  16384
#define AEM_SMTP_MAX_ADDRSIZE 100
#define AEM_SMTP_MAX_TO_ADDR 10

#define AEM_EHLO_RESPONSE_LEN 28
#define AEM_EHLO_RESPONSE \
"\r\n250-SIZE 15000" \
"\r\n250 AUTH" \
"\r\n"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtp.h"

static size_t smtp_addr(const size_t len, const char * const buf, char addr[AEM_SMTP_MAX_ADDRSIZE]) {
	size_t start = 1;
	size_t szAddr = len - 1;

	while (szAddr > 0 && buf[start - 1] != '<') {start++; szAddr--;}
	if (szAddr < 1) return 0;
	while (szAddr > 0 && buf[start + szAddr] != '>') szAddr--;
	if (szAddr < 1) return 0;

	if (szAddr > AEM_SMTP_MAX_ADDRSIZE) return 0;
	memcpy(addr, buf + start, szAddr);
	return szAddr;
}

static bool smtp_greet(const int sock, const size_t lenDomain, const char *domain) {
	const int lenGreet = 12 + lenDomain;
	char ourGreeting[lenGreet];
	memcpy(ourGreeting, "220 ", 4);
	memcpy(ourGreeting + 4, domain, lenDomain);
	memcpy(ourGreeting + 4 + lenDomain, " ESMPT\r\n", 8);
	return (send(sock, ourGreeting, lenGreet, 0) == lenGreet);
}

static bool smtp_helo(const int sock, const size_t lenDomain, const char *domain, const ssize_t bytes, const char *buf) {
	if (bytes < 4) return false;

	if (strncasecmp(buf, "EHLO", 4) == 0) {
		const ssize_t lenHelo = 4 + lenDomain + AEM_EHLO_RESPONSE_LEN;
		char helo[lenHelo];
		memcpy(helo, "250-", 4);
		memcpy(helo + 4, domain, lenDomain);
		memcpy(helo + 4 + lenDomain, AEM_EHLO_RESPONSE, AEM_EHLO_RESPONSE_LEN);
		return (send(sock, helo, lenHelo, 0) == lenHelo);
	} else if (strncasecmp(buf, "HELO", 4) == 0) {
		const ssize_t lenHelo = 6 + lenDomain;
		char helo[lenHelo];
		memcpy(helo, "250 ", 4);
		memcpy(helo + 4, domain, lenDomain);
		memcpy(helo + 4 + lenDomain, "\r\n", 2);
		return (send(sock, helo, lenHelo, 0) == lenHelo);
	}

	return false;
}

void smtp_fail(const int sock, const unsigned long ip) {
	send(sock, "421 Bye\r\n", 9, 0);
	close(sock);

	if (ip == 0) return;
	struct in_addr ip_addr; ip_addr.s_addr = ip;
	printf("[SMTP] Error receiving message (IP: %s)\n", inet_ntoa(ip_addr));
}

void respond_smtp(const int sock, const size_t lenDomain, const char *domain, const unsigned long ip) {
	puts("[SMTP] New connection");
	if (!smtp_greet(sock, lenDomain, domain)) return smtp_fail(sock, ip);

	char buf[AEM_SMTP_SIZE_BUF + 1];
	int bytes = recv(sock, buf, AEM_SMTP_SIZE_BUF, 0);

	if (!smtp_helo(sock, lenDomain, domain, bytes, buf)) return smtp_fail(sock, ip);

	const size_t lenGreeting = bytes - 7;
	char greeting[lenGreeting];
	memcpy(greeting, buf + 5, lenGreeting);

	size_t szFrom = 0, szTo = 0, toCount = 0;
	char from[AEM_SMTP_MAX_ADDRSIZE];
	char to[AEM_SMTP_MAX_ADDRSIZE * AEM_SMTP_MAX_TO_ADDR + AEM_SMTP_MAX_TO_ADDR];
	bzero(to, AEM_SMTP_MAX_ADDRSIZE * AEM_SMTP_MAX_TO_ADDR + AEM_SMTP_MAX_TO_ADDR);

	while(1) {
		bytes = recv(sock, buf, AEM_SMTP_SIZE_BUF, 0);

		if (bytes > 10 && strncasecmp(buf, "MAIL FROM:", 10) == 0) {
			szFrom = smtp_addr(bytes - 10, buf + 10, from);
			if (szFrom < 1) return smtp_fail(sock, ip);
		}

		else if (bytes > 8 && strncasecmp(buf, "RCPT TO:", 8) == 0) {
			if (toCount > AEM_SMTP_MAX_TO_ADDR) return smtp_fail(sock, ip);

			char newTo[AEM_SMTP_MAX_ADDRSIZE];
			size_t szNewTo = smtp_addr(bytes - 8, buf + 8, newTo);
			if (szNewTo < 1) return smtp_fail(sock, ip);

			if (toCount > 0) {
				to[szTo] = '\n';
				szTo++;
			}

			memcpy(to + szTo, newTo, szNewTo);
			szTo += szNewTo;
			toCount++;
		}

		else if (bytes >= 4 && strncasecmp(buf, "DATA", 4) == 0) {
			send(sock, "354 OK\r\n", 8, 0);
			break;
		}

		else if (bytes < 4 || strncasecmp(buf, "NOOP", 4) != 0) {
			struct in_addr ip_addr; ip_addr.s_addr = ip;
			printf("[SMTP] Terminating, unsupported command received: %.4s (IP: %s; greeting: %.*s)\n", buf, inet_ntoa(ip_addr), (int)lenGreeting, greeting);
			return smtp_fail(ip, 0);
		}

		send(sock, "250 OK\r\n", 8, 0);
	}

	char* msgBody = malloc(AEM_SMTP_SIZE_BUF + 1);
	size_t lenMsgBody = 0;

	while(1) {
		bytes = recv(sock, buf, AEM_SMTP_SIZE_BUF, 0);

		memcpy(msgBody + lenMsgBody, buf, bytes);
		lenMsgBody += bytes;

		if (lenMsgBody > 5 && memcmp(msgBody + lenMsgBody - 5, "\r\n.\r\n", 5) == 0) break;
	}

	msgBody[lenMsgBody] = '\0';

	send(sock, "250 OK\r\n", 8, 0);

	recv(sock, buf, 4, 0);
	if (strncasecmp(buf, "QUIT", 4) == 0) {
		send(sock, "221 Bye\r\n", 9, 0);
	} else {
		printf("[SMTP] Expected QUIT, got %.4s\n", buf);
		send(sock, "421 Bye\r\n", 9, 0);
	}

	close(sock);

	struct in_addr ip_addr; ip_addr.s_addr = ip;
	printf("[SMTP] IP=%s\n", inet_ntoa(ip_addr));
	printf("[SMTP] Greeting=%.*s\n", (int)lenGreeting, greeting);
	printf("[SMTP] From=%.*s\n", (int)szFrom, from);
	printf("[SMTP] To=%.*s\n", (int)szTo, to);
	printf("[SMTP] Message:\n%.*s\n", (int)lenMsgBody, msgBody);
	free(msgBody);
}
