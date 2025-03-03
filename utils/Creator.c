#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
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

static unsigned char *welcomeEnvelope(const struct evpKeys * const ek, size_t * const lenEvp) {
	const size_t lenMsg = AEM_MSG_HDR_SZ + 1 + AEM_WELCOME_MA_LEN;
	unsigned char msg[lenMsg];
	aem_msg_init(msg, AEM_MSG_TYPE_INT, 0);

	msg[AEM_MSG_HDR_SZ] = 192; // IntMsg InfoByte: System
	memcpy(msg + AEM_MSG_HDR_SZ + 1, AEM_WELCOME_MA, AEM_WELCOME_MA_LEN);

	aem_sign_message(msg, lenMsg, ek->usk);
	return msg2evp(msg, lenMsg, ek->pwk, NULL, 0, lenEvp);
}

static int createWelcome(const struct evpKeys * const ek, const unsigned char * const sbk) {
	// Create the MA's welcome Envelope
	size_t lenWm = 0;
	unsigned char * const wm = welcomeEnvelope(ek, &lenWm);
	if (wm == NULL) return -1;
	const uint16_t wmBc = (lenWm / AEM_EVP_BLOCKSIZE) - AEM_EVP_MINBLOCKS;

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
	memcpy(dec + (AEM_USERCOUNT * sizeof(uint16_t)), &wmBc, sizeof(uint16_t)); // Block count of first envelope

	const size_t lenEnc = lenDec + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, lenDec, NULL, 0, NULL, enc, stiKey);
	sodium_memzero(stiKey, crypto_aead_aegis256_KEYBYTES);

	return createFile("Stindex.aem", enc, lenEnc);
}

static int createAccount(const unsigned char smk[AEM_KDF_SMK_KEYLEN], const struct aem_user * const user) {
	// Get keys
	unsigned char abk[AEM_KDF_SUB_KEYLEN];
	aem_kdf_smk(abk, AEM_KDF_SUB_KEYLEN, AEM_KDF_KEYID_SMK_ACC, smk);

	unsigned char accKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(accKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_ACC_ACC, abk);
	sodium_memzero(abk, AEM_KDF_SUB_KEYLEN);

	// Create raw data
	const size_t lenDec = sizeof(uint16_t) + sizeof(struct aem_user);
	unsigned char dec[lenDec];
	bzero(dec, sizeof(uint16_t));
	memcpy(dec + sizeof(uint16_t), user, sizeof(struct aem_user));

	// Encrypt with Account Key
	const int lenEnc = lenDec + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, lenDec, NULL, 0, NULL, enc, accKey);
	sodium_memzero(accKey, crypto_aead_aegis256_KEYBYTES);
	sodium_memzero(dec, lenDec);

	const int ret = createFile("Account.aem", enc, lenEnc);
	return ret;
}

static void printKeys(const unsigned char smk[AEM_KDF_SMK_KEYLEN], const unsigned char ma_umk[AEM_KDF_UMK_KEYLEN]) {
	const int lenTxt = (MAX(AEM_KDF_UMK_KEYLEN, AEM_KDF_SMK_KEYLEN) * 2) + 1;
	char txt[lenTxt];

	sodium_bin2hex(txt, lenTxt, smk, AEM_KDF_SMK_KEYLEN);
	printf("Server Master Key: %s\n", txt);

	sodium_bin2base64(txt, lenTxt, ma_umk, AEM_KDF_UMK_KEYLEN, sodium_base64_VARIANT_ORIGINAL);
	printf("Master Admin UMK: %s\n", txt);

	sodium_memzero(txt, lenTxt);
}

static int createDirs(void) {
	if (mkdir("allears", S_IRWXU) != 0) {perror("Failed creating directory: allears"); return -1;}
	if (chdir("allears") != 0) {perror("Failed entering directory: allears"); return -1;}

	if (mkdir("bin", S_IRWXU) != 0) {perror("Failed creating directory: allears/bin"); return EXIT_FAILURE;}
	if (mkdir("cgroup", S_IRWXU) != 0) {perror("Failed creating directory: allears/cgroup"); return EXIT_FAILURE;}
	if (mkdir("mount", S_IRWXU) != 0) {perror("Failed creating directory: allears/mount"); return EXIT_FAILURE;}

	if (mkdir("Data", S_IRWXU) != 0) {perror("Failed creating directory: allears/Data"); return EXIT_FAILURE;}
	if (mkdir("Msg", S_IRWXU) != 0) {perror("Failed creating directory: allears/Msg"); return EXIT_FAILURE;}

	return 0;
}

static void genSmk(unsigned char * const smk, unsigned char * const ma_umk, struct aem_user * const user) {
	for(;;) { // Generate a valid SMK
		randombytes_buf(smk, AEM_KDF_SMK_KEYLEN);
		aem_kdf_smk(ma_umk, AEM_KDF_UMK_KEYLEN, AEM_KDF_KEYID_SMK_UMK, smk);
		aem_kdf_umk(user->uak, AEM_KDF_SUB_KEYLEN, AEM_KDF_KEYID_UMK_UAK, ma_umk);

		// SMK is valid if the Master Admin's UserID is zero (username 'aaa')
		if (aem_getUserId(user->uak) == 0) {
			user->level = AEM_USERLEVEL_MAX;

			// Set the public keys
			unsigned char secret[X25519_SKBYTES];
			aem_kdf_umk(secret, X25519_SKBYTES, AEM_KDF_KEYID_UMK_ESK, ma_umk);
			crypto_scalarmult_base(user->pwk, secret);
			sodium_memzero(secret, X25519_SKBYTES);
			break;
		}
	}
}

static int makeStorage(unsigned char * const smk, const struct aem_user * const user) {
	// Derive keys
	unsigned char sbk[AEM_KDF_SUB_KEYLEN]; // Storage Base Key
	aem_kdf_smk(sbk, AEM_KDF_SUB_KEYLEN, AEM_KDF_KEYID_SMK_STO, smk);

	unsigned char ssk[AEM_SSK_KEYLEN]; // Server Signature Key
	aem_kdf_sub(ssk, AEM_SSK_KEYLEN, AEM_KDF_KEYID_STO_SIG, sbk);

	setSigKey(ssk);
	sodium_memzero(ssk, AEM_SSK_KEYLEN);

	struct evpKeys ek;
	memcpy(ek.pwk, user->pwk, AEM_PWK_KEYLEN);
	memcpy(ek.usk, user->usk, AEM_USK_KEYLEN);

	const int ret = createWelcome(&ek, sbk);
	sodium_memzero(sbk, AEM_KDF_SUB_KEYLEN);
	sodium_memzero(ek.pwk, AEM_PWK_KEYLEN);
	sodium_memzero(ek.usk, AEM_USK_KEYLEN);

	delSigKey();
	if (ret != 0) {puts("Failed creating message"); return -1;}
	return 0;
}

int main(void) {
	puts("AEM-Creator: Sets up a new All-Ears Mail home folder.");
	printf("Bytes per user: %d (Private: %d)\n", sizeof(struct aem_user), AEM_LEN_PRIVATE);

	if (sodium_init() < 0) {puts("Failed sodium_init"); return 1;}
	if (createDirs() != 0) return 2;

	struct aem_user user;
	bzero(&user, sizeof(struct aem_user));

	unsigned char smk[AEM_KDF_SMK_KEYLEN];
	unsigned char ma_umk[AEM_KDF_UMK_KEYLEN];
	genSmk(smk, ma_umk, &user);

	printKeys(smk, ma_umk);

	if (makeStorage(smk, &user) != 0) return 4;
	if (createAccount(smk, &user) != 0) return 5;

	// Clean up
	sodium_memzero(&user, sizeof(struct aem_user));
	sodium_memzero(smk, AEM_KDF_SMK_KEYLEN);
	sodium_memzero(ma_umk, AEM_KDF_UMK_KEYLEN);

	puts("All done. Save the above keys, and move the newly-created allears folder to /var/lib/ on the server.");
	return 0;
}
