static bool terminate = false;

void tc_term(void) {
	terminate = true;
}

static bool peerOk(const int sock) {
	struct ucred peer;
	unsigned int lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.gid == getgid() && peer.uid == getuid());
}

static int bindSocket(const int sock) {
	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, AEM_SOCKPATH, AEM_SOCKPATH_LEN);
	return bind(sock, (struct sockaddr*)&addr, sizeof(addr.sun_family) + AEM_SOCKPATH_LEN);
}
