#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/AEM_KDF.h"
#include "../Common/Envelope.h"
#include "../Common/Message.h"
#include "../Common/Signature.h"
#include "../account/aem_user.h"

#define AEM_WELCOME_MA (const unsigned char * const)"Welcome, Master Administrator\nYou are the Master Administrator of this All-Ears Mail server. As such, your UserID is 0, which makes your username 'aaa'.\n\nUnlike other users, you cannot be demoted or deleted, and your UMK is derived directly from the SMK."
#define AEM_WELCOME_MA_LEN 254

// Master Admin UID=0, therefore we only need char #0
static char get_eid_char0(const unsigned char sbk[AEM_KDF_SUB_KEYLEN]) {
	const char b64_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_+";
	uint8_t src;
	aem_kdf_sub(&src, 1, AEM_KDF_KEYID_STO_EID, sbk);
	return b64_set[src & 63];
}

static int createFile(const char * const fn, const unsigned char * const data, const size_t lenData) {
	const int fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		printf("Failed creating file %s: %m\n", fn);
		return -1;
	}

	if (write(fd, data, lenData) != (ssize_t)lenData) {
		close(fd);
		printf("Failed writing file %s: %m\n", fn);
		return -1;
	}

	close(fd);
	printf("File created: %s\n", fn);
	return 0;
}

static unsigned char *welcomeEnvelope(const unsigned char epk[X25519_PKBYTES], size_t * const lenEnvelope) {
	const uint32_t ts = (uint32_t)time(NULL);
	*lenEnvelope = AEM_ENVELOPE_RESERVED_LEN + 6 + AEM_WELCOME_MA_LEN;
	const size_t padAmount = msg_getPadAmount(*lenEnvelope);
	*lenEnvelope += padAmount;

	unsigned char * const msg = malloc(*lenEnvelope);
	if (msg == NULL) return NULL;

	msg[AEM_ENVELOPE_RESERVED_LEN] = padAmount | 16; // 16=IntMsg
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 1, &ts, 4);
	msg[AEM_ENVELOPE_RESERVED_LEN + 5] = 192; // IntMsg InfoByte: System
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 6, AEM_WELCOME_MA, AEM_WELCOME_MA_LEN);
	bzero(msg + *lenEnvelope - padAmount, padAmount);

	message_into_envelope(msg, *lenEnvelope, epk, NULL, 0);
	return msg;
}

static int createWelcome(const unsigned char ma_epk[X25519_PKBYTES], const unsigned char * const sbk) {
	// Create the MA's welcome Envelope
	size_t lenWm = 0;
	unsigned char * const wm = welcomeEnvelope(ma_epk, &lenWm);
	if (wm == NULL) return -1;
	const uint16_t wmBc = (lenWm / 16) - AEM_ENVELOPE_MINBLOCKS;
	const uint16_t wmId = getEnvelopeId(wm);

	// Save the MA's Envelope file
	const char eid_char0 = get_eid_char0(sbk);
	const int ret = createFile((char[]){'M','s','g','/', eid_char0, eid_char0, '\0'}, wm, lenWm);
	free(wm);
	if (ret != 0) return -1;

	// Save Stindex.aem
	unsigned char stiKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(stiKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_STO_STI, sbk);

	const size_t lenDec = (AEM_USERCOUNT * sizeof(uint16_t)) + sizeof(uint16_t) * 2;
	unsigned char dec[lenDec];
	bzero(dec, lenDec);
	dec[0] = 1; // Envelope count 1 for the first user
	memcpy(dec + (AEM_USERCOUNT * sizeof(uint16_t)),                    &wmBc, sizeof(uint16_t)); // Block count of first envelope
	memcpy(dec + (AEM_USERCOUNT * sizeof(uint16_t)) + sizeof(uint16_t), &wmId, sizeof(uint16_t)); // EnvelopeID of first envelope

	const size_t lenEnc = lenDec + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, lenDec, NULL, 0, NULL, enc, stiKey);
	sodium_memzero(stiKey, crypto_aead_aegis256_KEYBYTES);

	return createFile("Stindex.aem", enc, lenEnc);
}

static int createAccount(const unsigned char smk[AEM_KDF_MASTER_KEYLEN], const struct aem_user * const users) {
	unsigned char abk[AEM_KDF_SUB_KEYLEN];
	aem_kdf_master(abk, AEM_KDF_SUB_KEYLEN, AEM_KDF_KEYID_SMK_ACC, smk);

	unsigned char accKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(accKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_ACC_ACC, abk);
	sodium_memzero(abk, AEM_KDF_SUB_KEYLEN);

	// Encrypt with Account Key
	const int lenEnc = (sizeof(struct aem_user) * AEM_USERCOUNT) + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char * const enc = malloc(lenEnc);
	if (enc == NULL) return -1;

	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, (const unsigned char * const)users, sizeof(struct aem_user) * AEM_USERCOUNT, NULL, 0, NULL, enc, accKey);
	sodium_memzero(accKey, crypto_aead_aegis256_KEYBYTES);

	const int ret = createFile("Account.aem", enc, lenEnc);
	free(enc);
	return ret;
}

static void printKeys(const unsigned char smk[AEM_KDF_MASTER_KEYLEN], const unsigned char ma_umk[AEM_KDF_MASTER_KEYLEN]) {
	const int lenTxt = AEM_KDF_MASTER_KEYLEN * 2 + 1;
	char txt[lenTxt];

	sodium_bin2hex(txt, lenTxt, smk, AEM_KDF_MASTER_KEYLEN);
	printf("Server Master Key: %s\n", txt);

	sodium_bin2base64(txt, lenTxt, ma_umk, AEM_KDF_MASTER_KEYLEN - 1, sodium_base64_VARIANT_ORIGINAL);
	printf("Master Admin UMK: %s\n", txt);

	sodium_memzero(txt, lenTxt);
}

static int createDirs(void) {
	if (mkdir("allears", S_IRWXU) != 0) {perror("Failed creating directory: allears"); return -1;}
	if (chdir("allears") != 0) {perror("Failed entering directory: allears"); return -1;}

	if (mkdir("bin", S_IRWXU) != 0) {perror("Failed creating directory: allears/bin"); return EXIT_FAILURE;}
	if (mkdir("cgroup", S_IRWXU) != 0) {perror("Failed creating directory: allears/cgroup"); return EXIT_FAILURE;}
	if (mkdir("mount", S_IRWXU) != 0) {perror("Failed creating directory: allears/mount"); return EXIT_FAILURE;}

	if (mkdir("Msg", S_IRWXU) != 0) {perror("Failed creating directory: allears/Storage/MSG"); return EXIT_FAILURE;}

	return 0;
}

static void genSmk(unsigned char * const smk, unsigned char * const ma_umk, struct aem_user * const users) {
	for(;;) { // Generate a valid SMK
		randombytes_buf(smk, AEM_KDF_MASTER_KEYLEN);
		aem_kdf_master(ma_umk, AEM_KDF_MASTER_KEYLEN, AEM_KDF_KEYID_SMK_UMK, smk);
		ma_umk[AEM_KDF_MASTER_KEYLEN - 1] = '\0';
		aem_kdf_master(users[0].uak, AEM_KDF_SUB_KEYLEN, AEM_KDF_KEYID_UMK_UAK, ma_umk);

		// SMK is valid if the Master Admin's UserID is zero (username 'aaa')
		if (aem_getUserId(users[0].uak) == 0) {
			users[0].level = AEM_USERLEVEL_MAX;

			// Set the EPK
			unsigned char esk[crypto_scalarmult_SCALARBYTES];
			aem_kdf_master(esk, crypto_scalarmult_SCALARBYTES, AEM_KDF_KEYID_UMK_ESK, ma_umk);
			crypto_scalarmult_base(users[0].epk, esk);
			sodium_memzero(esk, crypto_scalarmult_SCALARBYTES);
			break;
		}
	}
}

static int makeStorage(unsigned char * const smk, const struct aem_user * const users) {
	// Derive keys
	unsigned char sbk[AEM_KDF_SUB_KEYLEN];
	aem_kdf_master(sbk, AEM_KDF_SUB_KEYLEN, AEM_KDF_KEYID_SMK_STO, smk);

	unsigned char sigKey[AEM_SIG_KEYLEN];
	aem_kdf_sub(sigKey, AEM_SIG_KEYLEN, AEM_KDF_KEYID_STO_SIG, sbk);
	setSigKey(sigKey);
	sodium_memzero(sigKey, AEM_SIG_KEYLEN);

	if (createWelcome(users[0].epk, sbk) != 0) {puts("Failed creating message"); return -1;}

	sodium_memzero(sbk, AEM_KDF_SUB_KEYLEN);
	delSigKey();
	return 0;
}

int main(void) {
	puts("AEM-Creator - Sets up a new All-Ears Mail home folder.");

	if (sodium_init() < 0) {puts("Failed sodium_init"); return 1;}
	if (createDirs() != 0) return 2;

	struct aem_user * const users = malloc(sizeof(struct aem_user) * AEM_USERCOUNT);
	if (users == NULL) {puts("Failed allocation"); return 3;}
	bzero(users, sizeof(struct aem_user) * AEM_USERCOUNT);

	unsigned char smk[AEM_KDF_MASTER_KEYLEN];
	unsigned char ma_umk[AEM_KDF_MASTER_KEYLEN];
	genSmk(smk, ma_umk, users);

	printKeys(smk, ma_umk);

	if (makeStorage(smk, users) != 0) return 4;
	if (createAccount(smk, users) != 0) return 5;

	// Clean up
	sodium_memzero(users, sizeof(struct aem_user));
	free(users);
	sodium_memzero(smk, AEM_KDF_MASTER_KEYLEN);
	sodium_memzero(ma_umk, AEM_KDF_MASTER_KEYLEN);

	puts("All done. Save the above keys, and move the newly-created allears folder to /var/lib/ on the server.");
	return 0;
}
