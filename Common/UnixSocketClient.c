#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sodium.h>

#include "../Global.h"
#include "../Data/internal.h"

static pid_t pid_account = 0;
static pid_t pid_storage = 0;
static pid_t pid_enquiry = 0;

void setAccountPid(const pid_t pid) {pid_account = pid;}
void setStoragePid(const pid_t pid) {pid_storage = pid;}
void setEnquiryPid(const pid_t pid) {pid_enquiry = pid;}

static bool peerOk(const int sock, const pid_t pid) {
	struct ucred peer;
	socklen_t lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.pid == pid && peer.gid == getgid() && peer.uid == getuid());
}

static int getUnixSocket(const char * const path, const pid_t pid, const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	if (pid == 0) return -1;

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

	const ssize_t lenFinal = 1 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char final[lenFinal];
#ifdef AEM_API
	final[0] = 'A';
#elif defined(AEM_MTA)
	final[0] = 'M';
#else
	final[0] = '?';
#endif
	randombytes_buf(final + 1, crypto_secretbox_NONCEBYTES);

#ifdef AEM_API
	if      (pid == pid_account) crypto_secretbox_easy(final + 1 + crypto_secretbox_NONCEBYTES, clear, lenClear, final + 1, AEM_KEY_ACCESS_ACCOUNT_API);
	else if (pid == pid_storage) crypto_secretbox_easy(final + 1 + crypto_secretbox_NONCEBYTES, clear, lenClear, final + 1, AEM_KEY_ACCESS_STORAGE_API);
	else if (pid == pid_enquiry) crypto_secretbox_easy(final + 1 + crypto_secretbox_NONCEBYTES, clear, lenClear, final + 1, AEM_KEY_ACCESS_ENQUIRY_API);
#elif defined(AEM_MTA)
	if      (pid == pid_account) crypto_secretbox_easy(final + 1 + crypto_secretbox_NONCEBYTES, clear, lenClear, final + 1, AEM_KEY_ACCESS_ACCOUNT_MTA);
	else if (pid == pid_storage) crypto_secretbox_easy(final + 1 + crypto_secretbox_NONCEBYTES, clear, lenClear, final + 1, AEM_KEY_ACCESS_STORAGE_MTA);
	else if (pid == pid_enquiry) crypto_secretbox_easy(final + 1 + crypto_secretbox_NONCEBYTES, clear, lenClear, final + 1, AEM_KEY_ACCESS_ENQUIRY_MTA);
#endif

	if (send(sock, final, lenFinal, 0) != lenFinal) {
		syslog(LOG_ERR, "Failed sending data to %s", path);
		close(sock);
		return -1;
	}

	return sock;
}

int accountSocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	return getUnixSocket(AEM_SOCKPATH_ACCOUNT, pid_account, command, msg, lenMsg);
}

int storageSocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	return getUnixSocket(AEM_SOCKPATH_STORAGE, pid_storage, command, msg, lenMsg);
}

int enquirySocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	return getUnixSocket(AEM_SOCKPATH_ENQUIRY, pid_enquiry, command, msg, lenMsg);
}
