/*
Generate DKIM private keys:
openssl genrsa -out Admin.dkim 2048
openssl genrsa -out Users.dkim 2048

Generate DKIM public keys:
openssl rsa -in Admin.dkim -pubout -outform PEM -out Admin.pub
openssl rsa -in Users.dkim -pubout -outform PEM -out Users.pub

DNS:
admin._domainkey
users._domainkey
*/


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
	if (argc < 3) {printf("Usage: %s Admin.dkim Users.dkim\n", argv[0]); return 1;}

	off_t admSize;
	off_t usrSize;
	unsigned char admData[AEM_MAXSIZE_FILE];
	unsigned char usrData[AEM_MAXSIZE_FILE];

	rdFile(argv[1], admData, &admSize);
	rdFile(argv[2], usrData, &usrSize);

	puts("#ifndef AEM_DATA_DKIM_H");
	puts("#define AEM_DATA_DKIM_H");
	puts("");

	printf("#define AEM_DKIM_ADM_SIZE %ld\n", admSize);
	printf("#define AEM_DKIM_USR_SIZE %ld\n", usrSize);
	puts("");

	printKey("AEM_DKIM_ADM_DATA", admData, admSize);
	printKey("AEM_DKIM_USR_DATA", usrData, usrSize);

	puts("");
	puts("#endif");

	return 0;
}
