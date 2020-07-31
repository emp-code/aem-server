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
	servAddr.sin_port = htons(AEM_PORT);

	const int intTrue = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,   (const void*)&intTrue, sizeof(int)) != 0) return -1;
	if (setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, (const void*)&intTrue, sizeof(int)) != 0) return -1;

#ifdef AEM_API_ONI
	// Tor: loopback only
	servAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) != 0) return -1;
	if (setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, (const void*)&intTrue, sizeof(int)) != 0) return -1;
#else
	// Clearnet: bind to first non-loopback interface
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	struct if_nameindex * const ni = if_nameindex();
	for (int i = 0;; i++) {
		if (ni[i].if_index == 0) return -1;
		if (strncmp(ni[i].if_name, "lo", 2) == 0) continue;
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ni[i].if_name, strlen(ni[i].if_name) + 1) != 0) return -1;
		break;
	}
	if_freenameindex(ni);
#endif

	if (bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) return -1;
	if (setCaps(0, 0) != 0) return -1;
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
