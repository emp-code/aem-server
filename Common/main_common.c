// Common functions for Web/API/MTA main.c

static int setCaps(const bool allowBind) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	cap_t caps = cap_get_proc();
	if (cap_clear(caps) != 0) {cap_free(caps); return -1;}

	if (allowBind) {
		const cap_value_t capBind = CAP_NET_BIND_SERVICE;
		if (cap_set_flag(caps, CAP_PERMITTED, 1, &capBind, CAP_SET) != 0) {cap_free(caps); return -1;}
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &capBind, CAP_SET) != 0) {cap_free(caps); return -1;}
	}

	if (cap_set_proc(caps) != 0) {cap_free(caps); return -1;}

	return cap_free(caps);
}

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

	const int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));

	if (bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) return -1;
	if (setCaps(false) != 0) return -1;

	listen(sock, AEM_BACKLOG);
	return 0;
}

static void takeConnections(void) {
	const int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (initSocket(sock) != 0) {syslog(LOG_ERR, "Failed initSocket"); close(sock); return;}
	if (tlsSetup() != 0) {syslog(LOG_ERR, "Failed setting up TLS"); close(sock); return;}

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

	tlsFree();
	close(sock);
}
