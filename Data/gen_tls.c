#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for read

#define AEM_MAXSIZE_FILE 8192

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

static void printKey(const char * const def, unsigned char * const buf, const size_t len) {
	printf("#define %s (const unsigned char[]) {", def);

	for (size_t i = 0; i < len; i++) {
		printf("'\\x%.2x'", buf[i]);
		if (i < (len - 1)) printf(",");
	}

	puts("}");
}

int main(int argc, char *argv[]) {
	if (argc < 3
	|| (strlen(argv[1]) < 5 || strcmp(argv[1] + strlen(argv[1]) - 4, ".crt"))
	|| (strlen(argv[2]) < 5 || strcmp(argv[2] + strlen(argv[2]) - 4, ".key"))
	) {printf("Usage: %s TLS.crt TLS.key\n", argv[0]); return 1;}

	off_t crtSize;
	off_t keySize;
	unsigned char crtData[AEM_MAXSIZE_FILE];
	unsigned char keyData[AEM_MAXSIZE_FILE];

	rdFile(argv[1], crtData, &crtSize);
	rdFile(argv[2], keyData, &keySize);

	puts("#ifndef AEM_DATA_TLS_H");
	puts("#define AEM_DATA_TLS_H");
	puts("");

	printf("#define AEM_TLS_CRT_SIZE %ld\n", crtSize);
	printf("#define AEM_TLS_KEY_SIZE %ld\n", keySize);
	puts("");

	printKey("AEM_TLS_CRT_DATA", crtData, crtSize);
	printKey("AEM_TLS_KEY_DATA", keyData, keySize);

	puts("");
	puts("#endif");

	return 0;
}
