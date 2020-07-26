static bool peerOk(const int sock, const pid_t pid) {
	struct ucred peer;
	socklen_t lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.pid == pid && peer.gid == getgid() && peer.uid == getuid());
}

static int getUnixSocket(const char * const path, const pid_t pid, const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_WARNING, "Failed creating Unix socket: %m"); return -1;}

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, path, AEM_SOCKPATH_LEN);

	if (connect(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + AEM_SOCKPATH_LEN) == -1) {
		syslog(LOG_WARNING, "Failed connecting to Unix socket: %m");
		close(sock);
		return -1;
	}

	if (!peerOk(sock, pid)) {
		syslog(LOG_WARNING, "Invalid Unix socket peer");
		close(sock);
		return -1;
	}

	const size_t lenClear = 1 + lenMsg;
	unsigned char clear[lenClear];
	clear[0] = command;
	if (msg != NULL) memcpy(clear + 1, msg, lenMsg);

	const ssize_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);

	if      (pid == pid_account) crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_account);
	else if (pid == pid_storage) crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_storage);
#ifdef AEM_API
	else if (pid == pid_enquiry) crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_enquiry);
#endif

	if (send(sock, encrypted, lenEncrypted, 0) != lenEncrypted) {
		syslog(LOG_ERR, "Failed sending data to %s", path);
		close(sock);
		return -1;
	}

	return sock;
}

static int accountSocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	return getUnixSocket(AEM_SOCKPATH_ACCOUNT, pid_account, command, msg, lenMsg);
}

static int storageSocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	return getUnixSocket(AEM_SOCKPATH_STORAGE, pid_storage, command, msg, lenMsg);
}

#ifdef AEM_API
static int enquirySocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	return getUnixSocket(AEM_SOCKPATH_ENQUIRY, pid_enquiry, command, msg, lenMsg);
}
#endif
