#define AEM_SMTP_MAXSIZE_FROM 99
#define AEM_SMTP_MAXSIZE_TO   99

#define AEM_SMTP_SIZE_BUF  16384
#define AEM_SMTP_MAX_MSGSIZE "15000" // 5 digits
#define AEM_SMTP_MAX_ADDRSIZE 100
#define AEM_SMTP_MAX_TO_ADDR 10

#define AEM_SMTP_SIZE_COMMAND_FROM 10 // MAIL FROM:
#define AEM_SMTP_SIZE_COMMAND_TO 8 // RCPT TO:

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtp.h"

static int smtp_addr(const size_t cmdSize, size_t len, char buf[AEM_SMTP_SIZE_BUF], char addr[AEM_SMTP_MAX_ADDRSIZE], const size_t offset) {
	size_t start = cmdSize;
	size_t szAddr = len - start;

	while (szAddr > 0 && buf[start - 1] != '<') {start++; szAddr--;}
	if (szAddr < 1) return -1;
	while (szAddr > 0 && buf[start + szAddr] != '>') szAddr--;
	if (szAddr < 1) return -1;

	if (szAddr > AEM_SMTP_MAX_ADDRSIZE) return -1;
	memcpy(addr + offset, buf + start, szAddr);
	return szAddr;
}

void respond_smtp(const int sock, const unsigned long ip) {
	struct in_addr ip_addr;
	ip_addr.s_addr = ip;
	printf("[SMTP] New connection from %s\n", inet_ntoa(ip_addr));

	send(sock, "220 allears.test\r\n", 18, 0);

	char buf[AEM_SMTP_SIZE_BUF + 1];
	int bytes = recv(sock, buf, AEM_SMTP_SIZE_BUF, 0);

	if (bytes < 4) {close(sock); return;}
	if (strncasecmp(buf, "EHLO", 4) == 0) {
		send(sock,
			"250-allears.test\r\n"
			"250-SIZE "AEM_SMTP_MAX_MSGSIZE"\r\n"
			"250 AUTH\r\n"
		, 44, 0);
	} else if (strncasecmp(buf, "HELO", 4) == 0) {
		send(sock, "250 allears.test\r\n", 8, 0);
	} else {close(sock); return;}

	size_t szFrom = 0, szTo = 0, toCount = 0;
	char from[AEM_SMTP_MAX_ADDRSIZE];
	char to[AEM_SMTP_MAX_ADDRSIZE * AEM_SMTP_MAX_TO_ADDR];
	bzero(to, AEM_SMTP_MAX_ADDRSIZE * AEM_SMTP_MAX_TO_ADDR);

	const size_t lenGreeting = bytes - 7;
	char greeting[lenGreeting];
	memcpy(greeting, buf + 5, lenGreeting);

	while(1) {
		bytes = recv(sock, buf, AEM_SMTP_SIZE_BUF, 0);

		if (bytes > 10 && strncasecmp(buf, "MAIL FROM:", 10) == 0) {
			szFrom = smtp_addr(AEM_SMTP_SIZE_COMMAND_FROM, bytes, buf, from, 0);
			if (szFrom <= 0) {close(sock); return;}
		}

		else if (bytes > 9 && strncasecmp(buf, "RCPT TO:", 8) == 0) {
			if (toCount > AEM_SMTP_MAX_TO_ADDR) {close(sock); return;}

			szTo = smtp_addr(AEM_SMTP_SIZE_COMMAND_TO, bytes, buf, to, toCount * AEM_SMTP_MAX_ADDRSIZE);
			if (szTo <= 0) {close(sock); return;}

			toCount++;
		}

		else if (bytes >= 4 && strncasecmp(buf, "DATA", 4) == 0) {
			send(sock, "354 OK\r\n", 8, 0);
			break;
		}

		else if (bytes < 4 || strncasecmp(buf, "NOOP", 4) != 0) {
			printf("[SMTP] Terminating, unsupported command received: %.4s\n", buf);
			close(sock);
			return;
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

	printf("[SMTP] Greeting=%.*s\n", (int)lenGreeting, greeting);
	printf("[SMTP] From=%.*s\n", (int)szFrom, from);
	printf("[SMTP] To=%.*s\n", (int)szTo, to);
	printf("[SMTP] Message:\n%.*s\n", (int)lenMsgBody, msgBody);
	free(msgBody);
}
