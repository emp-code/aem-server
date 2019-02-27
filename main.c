#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "defines.h"

//#include "aef.h"
#include "http.h"
//#include "https.h"
//#include "smtp.h"

// Allow restarting the server immediately after kill
static void allowQuickRestart(const int* sock) {
	const int optval = 1;
	setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));
}

static int initSocket(const int sock, const int port) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int ret = bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(sock, 10); // socket, backlog (# of connections to keep in queue)
	return 0;
}

static int receiveConnections(const int port) {
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		puts("ERROR: Opening socket failed");
		return 1;
	}

	allowQuickRestart(&sock);

	if (initSocket(sock, port) != 0) {
		puts("ERROR: Binding socket failed");
		return 1;
	}

	struct sockaddr_in cliAddr;
	socklen_t cliLen = sizeof(cliAddr);

	// Loop to accept connections on the socket
	while(1) {
		const int sockNew = accept(sock, (struct sockaddr*)&cliAddr, &cliLen);
		if (sockNew < 0) {puts("ERROR: Failed to create socket for accepting connection"); return -1;}

		switch(port) {
//			case AEM_PORT_SMTP: respond_smtp(sockNew); break; 
			case AEM_PORT_HTTP: respond_http(sockNew); break;
//			case AEM_PORT_HTTPS: respond_https(sockNew); break;
//			case AEM_PORT_AEF: respond_aef(); break;
		}

		close(sockNew);
	}

	close(sock);
	return 0;
}

static int forkReceiver(const int port) {
	const int pid = fork();
	if (pid < 0) return pid;
	if (pid == 0) receiveConnections(port);
	return 0;
}

int main() {
	puts(">>> ae-mail: All-Ears Mail");

//	if (forkReceiver(AEM_PORT_HTTPS) < 0)  return 1;
//	if (forkReceiver(AEM_PORT_HTTPS) < 0)  return 1;
//	if (forkReceiver(AEM_PORT_SMTP) < 0)  return 1;
//	if (forkReceiver(AEM_PORT_AEF) < 0)  return 1;

	receiveConnections(AEM_PORT_HTTP);

	return 0;
}
