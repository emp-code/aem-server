#ifndef AEM_STORAGE_IO_H
#define AEM_STORAGE_IO_H

int storage_erase(const unsigned char * const upk);
int storage_delete(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char * const id);
int storage_write(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], unsigned char * const data, const uint16_t sze);
int storage_read(const unsigned char * const upk, const unsigned char * const matchId, unsigned char ** const msgData);

int ioSetup(const unsigned char * const storageKey);
void ioFree(void);

#endif
