// Common functions for Web/API/MTA main.c

static void setSocketTimeout(const int sock) {
	struct timeval tv;
	tv.tv_sec = AEM_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

__attribute__((warn_unused_result))
static int initSocket(const int sock) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(AEM_PORT);

	const int intTrue = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,   (const void*)&intTrue, sizeof(int));
	setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, (const void*)&intTrue, sizeof(int));

#ifdef AEM_API_ONI
	setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3); // Tor: loopback only
	setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, (const void*)&intTrue, sizeof(int));
#endif

	if (bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) return -1;
	if (setCaps(0) != 0) return -1;
	return listen(sock, AEM_BACKLOG);
}

static void acceptClients(void) {
	const int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (initSocket(sock) != 0) {syslog(LOG_ERR, "Failed initSocket"); close(sock); return;}

	syslog(LOG_INFO, "Ready");

#ifdef AEM_MTA
	struct sockaddr_in clientAddr;
	unsigned int clen = sizeof(clientAddr);
#endif

	while (!terminate) {
#ifdef AEM_MTA
		const int newSock = accept4(sock, (struct sockaddr*)&clientAddr, &clen, SOCK_CLOEXEC);
#else
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
#endif

		if (newSock < 0) {syslog(LOG_ERR, "Failed creating socket"); continue;}
		setSocketTimeout(newSock);

#ifdef AEM_MTA
		respondClient(newSock, &clientAddr);
#else
		respondClient(newSock);
#endif

		close(newSock);
	}

	close(sock);
}
