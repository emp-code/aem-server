__attribute__((warn_unused_result))
static int pipeReadSmall(void * const out, const ssize_t len) {
	const ssize_t r = read(AEM_FD_PIPE_RD, out, len);
	if (r != len) {
		syslog(LOG_ERR, "PipeRead: Expected %zd bytes, received %zd", len, r);
		return -1;
	}

	return 0;
}

#ifndef AEM_PIPE_NOLARGE
__attribute__((warn_unused_result))
static int pipeReadLarge(unsigned char * const out, size_t * const len) {
	if (read(AEM_FD_PIPE_RD, (unsigned char*)len, sizeof(size_t)) != sizeof(size_t)) return -1;

	ssize_t tbr = *len;
	while (tbr > 0) {
		if (tbr > PIPE_BUF) {
			if (read(AEM_FD_PIPE_RD, out + (*len - tbr), PIPE_BUF) != PIPE_BUF) return -1;
			tbr -= PIPE_BUF;
		} else {
			if (read(AEM_FD_PIPE_RD, out + (*len - tbr), tbr) != (ssize_t)tbr) return -1;
			break;
		}
	}

	return 0;
}
#endif
