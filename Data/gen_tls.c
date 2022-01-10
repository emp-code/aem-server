#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for read

#include "../Common/memeq.h"

#define AEM_MAXSIZE_FILE 8192

#include "../Common/RdFile.c"
#include "../Common/PrintDef.c"

int main(int argc, char *argv[]) {
	if (argc != 3
	|| (strlen(argv[1]) < 5 || !memeq(argv[1] + strlen(argv[1]) - 4, ".crt", 4))
	|| (strlen(argv[2]) < 5 || !memeq(argv[2] + strlen(argv[2]) - 4, ".key", 4))
	) {fprintf(stderr, "Usage: %s TLS.crt TLS.key\n", argv[0]); return 1;}

	off_t crtSize = 0;
	off_t keySize = 0;
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

	printDef("AEM_TLS_CRT_DATA", crtData, crtSize);
	printDef("AEM_TLS_KEY_DATA", keyData, keySize);
	puts("");

	puts("#endif");

	return 0;
}
