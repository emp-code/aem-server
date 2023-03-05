#include <sys/socket.h>
#include <unistd.h>

#include "peerok.h"

bool peerOk(const int sock
	#ifdef AEM_PEEROK_CLIENT
	, const pid_t peerPid
	#endif
) {
	struct ucred peer;
	socklen_t lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;

	return (peer.gid == getgid() && peer.uid == getuid()
		#ifdef AEM_PEEROK_CLIENT
		&& peer.pid == peerPid
		#endif
	);
}
