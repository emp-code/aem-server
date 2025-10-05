#include <ctype.h>
#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/Addr32.h"

int main(int argc, char *argv[]) {
	if (argc != 2) {fprintf(stderr, "Usage: %s address-list.txt\n", argv[0]); return EXIT_FAILURE;}

	// Print the header file
	const int fdTxt = open(argv[1], O_RDONLY);
	if (fdTxt < 0) {fprintf(stderr, "Failed to open %s\n", argv[1]); return EXIT_FAILURE;}

	const off_t len = lseek(fdTxt, 0, SEEK_END);
	if (len < 0) {fprintf(stderr, "Failed to read %s\n", argv[1]); return EXIT_FAILURE;}
	unsigned char data[len];
	if (pread(fdTxt, data, len, 0) != len) {fputs("Failed read", stderr); return EXIT_FAILURE;}

	int lineCount = 0;
	for (off_t i = 0; i < len; i++) {
		if (data[i] == '\n') lineCount++;
	}

	printf("#define AEM_ADMIN_ADDR_DEFAULT (unsigned char[]){\\\n");

	unsigned int entries = 0;
	const unsigned char *s = data;
	for (int i = 0; i < lineCount; i++) {
		const unsigned char * const lf = memchr(s, '\n', (data + len) - s);
		if (lf == NULL) break;

		const size_t lenSrc = lf - s;
		if (lenSrc < 16) {
			unsigned char addr32[10];
			addr32_store(addr32, s, lenSrc);
			if (entries != 0) printf(",\\\n");
			printf("0x%.2x,0x%.2x,0x%.2x,0x%.2x,0x%.2x,0x%.2x,0x%.2x,0x%.2x,0x%.2x,0x%.2x /*%.*s*/", addr32[0], addr32[1], addr32[2], addr32[3], addr32[4], addr32[5], addr32[6], addr32[7], addr32[8], addr32[9], lenSrc, s);
			entries++;
		}

		s = lf + 1;
	}

	puts("}");
	printf("#define AEM_ADMIN_ADDR_DEFAULT_COUNT %u\n", entries);

	close(fdTxt);
	return 0;
}
