#ifndef AEM_INCLUDES_FILE_H
#define AEM_INCLUDES_FILE_H

struct aem_file {
	char *filename;
	char *data;
	size_t lenData;
};

struct aem_fileSet {
	struct aem_file *cssFiles;
	struct aem_file *imgFiles;
	struct aem_file *jsFiles;

	int cssCount;
	int imgCount;
	int jsCount;
};

#endif
