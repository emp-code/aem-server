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

#include "../Common/RdFile.c"
#include "../Common/PrintDef.c"

int main(int argc, char *argv[]) {
	if (argc != 3) {fprintf(stderr, "Usage: %s Admin.dkim Users.dkim\n", argv[0]); return 1;}

	off_t admSize = 0;
	off_t usrSize = 0;
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

	printDef("AEM_DKIM_ADM_DATA", admData, admSize);
	printDef("AEM_DKIM_USR_DATA", usrData, usrSize);

	puts("");
	puts("#endif");

	return 0;
}
