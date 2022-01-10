static int rdFile(const char * const path, unsigned char * const data, off_t * const size) {
	const int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;

	*size = read(fd, data, AEM_MAXSIZE_FILE);
	close(fd);
	if (*size < 1) return -1;

	data[*size] = '\0';
	(*size)++;
	return 0;
}
