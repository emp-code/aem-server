static bool peerOk(const int sock) {
	// TODO: Verify peer PID (get Account/Storage PID from Manager at startup)
	struct ucred peer;
	socklen_t lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.gid == getgid() && peer.uid == getuid());
}

static int getUnixSocket(const char * const path) {
	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) return -1;

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, path);

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_WARNING, "Failed connecting to Unix socket");
		close(sock);
		return -1;
	}

	if (!peerOk(sock)) {
		syslog(LOG_WARNING, "Invalid Unix socket peer");
		close(sock);
		return -1;
	}

	return sock;
}
