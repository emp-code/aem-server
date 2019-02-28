#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "defines.h"

//#include "aef.h"
#include "http.h"
#include "https.h"
//#include "smtp.h"

// Allow restarting the server immediately after kill
static void allowQuickRestart(const int* sock) {
	const int optval = 1;
	setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));
}

static int initSocket(int *sock, const int port) {
	*sock = socket(AF_INET, SOCK_STREAM, 0);
	if (*sock < 0) {
		puts("ERROR: Opening socket failed");
		return 1;
	}

	allowQuickRestart(sock);

	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int ret = bind(*sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(*sock, 10); // socket, backlog (# of connections to keep in queue)
	return 0;
}

/*static int receiveConnections_aef() {
	int sock;
	if (initSocket(&sock, AEM_PORT_AEF) != 0) return 1;

	while(1) {
		const int sockNew = accept(sock, NULL, NULL);
		respond_aef(sockNew);
		close(sockNew);
	}

	return 0;
}*/

static int receiveConnections_http() {
	int sock;
	if (initSocket(&sock, AEM_PORT_HTTP) != 0) return 1;

	while(1) {
		const int sockNew = accept(sock, NULL, NULL);
		respond_http(sockNew);
		close(sockNew);
	}

	return 0;
}

static int receiveConnections_https(const int port) {
	int sock;
	if (initSocket(&sock, port) != 0) return 1;

	// Load certs
	FILE *f = fopen("aem-https.crt", "r");
	fseek(f, 0L, SEEK_END);
	long lenHttpsCert = ftell(f);
	rewind(f);

	unsigned char *httpsCert = calloc(lenHttpsCert + 2, 1);
	size_t readBytes = fread(httpsCert, 1, lenHttpsCert, f);
	fclose(f);

	if (readBytes != lenHttpsCert) {
		free(httpsCert);
		return 2;
	}

	// Load key
	f = fopen("aem-https.key", "r");
	fseek(f, 0L, SEEK_END);
	long lenHttpsKey = ftell(f);
	rewind(f);
	
	unsigned char *httpsKey = calloc(lenHttpsKey + 2, 1);
	readBytes = fread(httpsKey, 1, lenHttpsKey, f);
	fclose(f);

	if (readBytes != lenHttpsKey) {
		free(httpsCert);
		free(httpsKey);
		return 3;
	}

	while(1) {
		const int sockNew = accept(sock, NULL, NULL); 
		respond_https(sockNew, httpsCert, lenHttpsCert + 1, httpsKey, lenHttpsKey + 1);
		close(sockNew);
	}

	return 0;
}

/*static int receiveConnections_smtp() {
	int sock;
	if (initSocket(&sock, AEM_PORT_SMTP) != 0) return 1;

	while(1) {
		const int sockNew = accept(sock, NULL, NULL);
		respond_smtp(sockNew);
		close(sockNew);
	}

	return 0;
}*/

int main() {
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {puts("ERROR: signal failed"); return 4;} // Prevent zombie processes

	puts(">>> ae-mail: All-Ears Mail");

	int pid;
	
	pid = fork();
	if (pid < 0) return 1;
//	if (pid == 0) return receiveConnections(AEM_PORT_AEF);

	pid = fork();
	if (pid < 0) return 1;
	if (pid == 0) return receiveConnections_https(AEM_PORT_HTTPS);

	pid = fork();
	if (pid < 0) return 1;
//	if (pid == 0) return receiveConnections(AEM_PORT_SMTP);

	receiveConnections_http(AEM_PORT_HTTP);

	return 0;
}
