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
static int initSocket(const int sock, const int port, const int backlog) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));

	if (bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) return -1;
	if (setCaps(false) != 0) return -1;

	listen(sock, backlog);
	return 0;
}

__attribute__((warn_unused_result))
static int getDomainFromCert(void) {
	char certInfo[1024];
	mbedtls_x509_crt_info(certInfo, 1024, "AEM_", &tlsCrt);

	const char *c = strstr(certInfo, "\nAEM_subject name");
	if (c == NULL) return -1;
	c += 17;

	const char * const end = strchr(c, '\n');

	c = strstr(c, ": CN=");
	if (c == NULL || c > end) return -1;
	c += 5;

	return setDomain(c, end - c);
}
