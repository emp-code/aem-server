// For handling large reads on O_DIRECT pipes
static ssize_t pipeReadDirect(const int fd, unsigned char * const buf, const size_t maxLen) {
	ssize_t readBytes = 0;

	while(1) {
		const ssize_t ret = read(fd, buf + readBytes, maxLen - readBytes);
		if (ret < 1) return -1;

		readBytes += ret;
		if (ret != PIPE_BUF) return readBytes;
	}
}

__attribute__((warn_unused_result))
static int pipeRead(const int fd, unsigned char ** const target, size_t * const len) {
	unsigned char buf[AEM_PIPE_BUFSIZE];
	const off_t readBytes = pipeReadDirect(fd, buf, AEM_PIPE_BUFSIZE);
	if (readBytes < AEM_MINLEN_PIPEREAD) return -1;

	*len = readBytes;
	*target = sodium_malloc(*len);
	if (*target == NULL) return -1;
	memcpy(*target, buf, *len);
	sodium_mprotect_readonly(*target);

	sodium_memzero(buf, AEM_PIPE_BUFSIZE);
	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadTls(const int fd) {
	unsigned char *crtData;
	unsigned char *keyData;
	size_t crtLen;
	size_t keyLen;

	if (
	   pipeRead(fd, &crtData, &crtLen) != 0
	|| pipeRead(fd, &keyData, &keyLen) != 0
	) return -1;

	const int ret = tlsSetup(crtData, crtLen, keyData, keyLen);

	sodium_free(crtData);
	sodium_free(keyData);
	return ret;
}