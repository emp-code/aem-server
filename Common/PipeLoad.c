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
	if (
	   pipeRead(fd, &tls_crt, &len_tls_crt) != 0
	|| pipeRead(fd, &tls_key, &len_tls_key) != 0
	) return -1;

	mbedtls_x509_crt_init(&tlsCrt);
	int ret = mbedtls_x509_crt_parse(&tlsCrt, tls_crt, len_tls_crt);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_x509_crt_parse failed: %d", ret); return -1;}

	mbedtls_pk_init(&tlsKey);
	ret = mbedtls_pk_parse_key(&tlsKey, tls_key, len_tls_key, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_pk_parse_key failed: %d", ret); return -1;}

	if (getDomainFromCert() != 0) {syslog(LOG_ERR, "Failed getting domain from certificate"); return -1;}

	return 0;
}
