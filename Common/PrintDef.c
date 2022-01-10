static void printDef(const char * const def, unsigned char * const buf, const size_t len) {
	printf("#define %s (const unsigned char[]) {", def);

	for (size_t i = 0; i < len; i++) {
		printf("'\\x%.2x'", buf[i]);
		if (i < (len - 1)) printf(",");
	}

	puts("}");
}
