#ifdef AEM_ACCOUNT
	#define AEM_SOCKPATH AEM_SOCKPATH_ACCOUNT
	#define AEM_ACCESSKEY_API AEM_KEY_ACCESS_ACCOUNT_API
	#define AEM_ACCESSKEY_MTA AEM_KEY_ACCESS_ACCOUNT_MTA
#elif defined(AEM_ENQUIRY)
	#define AEM_SOCKPATH AEM_SOCKPATH_ENQUIRY
	#define AEM_ACCESSKEY_API AEM_KEY_ACCESS_ENQUIRY_API
	#define AEM_ACCESSKEY_MTA AEM_KEY_ACCESS_ENQUIRY_MTA
#elif defined(AEM_STORAGE)
	#define AEM_SOCKPATH AEM_SOCKPATH_STORAGE
	#define AEM_ACCESSKEY_API AEM_KEY_ACCESS_STORAGE_API
	#define AEM_ACCESSKEY_MTA AEM_KEY_ACCESS_STORAGE_MTA
#endif

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

static void conn_api(const int sock, const unsigned char * const dec, const size_t lenDec);
static void conn_mta(const int sock, const unsigned char * const dec, const size_t lenDec);

void takeConnections(void) {
	const int sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) return;
	listen(sockListen, 50);

	while (!terminate) {
		const int sock = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sock < 0) continue;

		if (!peerOk(sock)) {
			syslog(LOG_WARNING, "Connection rejected from invalid peer");
			close(sock);
			continue;
		}

		unsigned char enc[AEM_SOCK_MAXLEN];
		const ssize_t lenEnc = recv(sock, enc, AEM_SOCK_MAXLEN, 0);
		if (lenEnc < AEM_SOCK_MINLEN) {syslog(LOG_ERR, "Peer sent too little data"); close(sock); continue;}
		const size_t lenDec = lenEnc - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES - 1;
		unsigned char dec[lenDec];

		if        (enc[0] == 'A' && crypto_secretbox_open_easy(dec, enc + 1 + crypto_secretbox_NONCEBYTES, lenDec + crypto_secretbox_MACBYTES, enc + 1, AEM_ACCESSKEY_API) == 0) {
			conn_api(sock, dec, lenDec);
		} else if (enc[0] == 'M' && crypto_secretbox_open_easy(dec, enc + 1 + crypto_secretbox_NONCEBYTES, lenDec + crypto_secretbox_MACBYTES, enc + 1, AEM_ACCESSKEY_MTA) == 0) {
			conn_mta(sock, dec, lenDec);
		} else {
			syslog(LOG_WARNING, "Failed decrypting message from peer (%zd bytes)", lenEnc);
		}

		close(sock);
	}

	close(sockListen);
}
