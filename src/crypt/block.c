#include <crypt/des.h>
#include <crypt/rand.h>
#include <crypt/block.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cr_bcphr_s {
	blkencrypt_t encrypt;
	blkdecrypt_t decrypt;
	enum cr_bcphr_mode mode;
	size_t blksz;
	size_t keysz;
	size_t written;
	uint8_t *block;
	uint8_t *iv;
	uint8_t *key;
};

struct cr_bcphr_s *cr_bcphr_new(const uint8_t *key,
				size_t keysz,
				size_t blksz,
				blkencrypt_t encrypt,
				blkdecrypt_t decrypt, enum cr_bcphr_mode mode)
{
	struct cr_bcphr_s *cipher;

	cipher = malloc(sizeof(struct cr_bcphr_s));
	if (cipher == NULL)
		goto out;

	cipher->block = malloc(blksz);
	if (cipher->block == NULL)
		goto cipher_clean;

	cipher->iv = malloc(blksz);
	if (cipher->iv == NULL)
		goto block_clean;

	if (cr_rand_bytes(cipher->iv, blksz) != 0)
		goto iv_clean;

	cipher->key = malloc(keysz);
	if (cipher->key == NULL)
		goto iv_clean;

	cipher->encrypt = encrypt;
	cipher->decrypt = decrypt;
	cipher->mode = mode;
	cipher->blksz = blksz;
	cipher->keysz = keysz;
	cipher->written = 0;
	memcpy(cipher->key, key, keysz);

	return cipher;

 iv_clean:
	free(cipher->iv);
 block_clean:
	free(cipher->block);
 cipher_clean:
	free(cipher);
 out:
	return NULL;
}

void cr_bcphr_destroy(struct cr_bcphr_s *cipher)
{
	free(cipher->block);
	free(cipher->iv);
	free(cipher->key);
	free(cipher);
}
//Notes to us: implement the returns for set_iv; get_iv; get_mode
size_t cr_bcphr_block_size(const struct cr_bcphr_s *cipher)
{
	return cipher->blksz;
}

void cr_bcphr_set_iv(struct cr_bcphr_s *cipher, const uint8_t *iv)
{
	size_t size = cr_bcphr_block_size(cipher);
	for(size_t i = 0; i < size; i++){
		cipher -> iv[i] = iv[i];
	}
	
}

size_t cr_bcphr_get_iv(const struct cr_bcphr_s *cipher, uint8_t *iv)
{
	size_t size = cr_bcphr_block_size(cipher);
	for(size_t i = 0; i < size; i++){
		iv[i] = cipher->iv[i];
	}
	return size;
}

enum cr_bcphr_mode cr_bcphr_get_mode(const struct cr_bcphr_s *cipher)
{

	return cipher->mode;//unsure
}

size_t cr_bcphr_encrypt(struct cr_bcphr_s *cipher, const uint8_t *plain,
			size_t len, uint8_t *out)
{
	return 0;
}

size_t cr_bcphr_decrypt(struct cr_bcphr_s *cipher, const uint8_t *ctext,
			size_t len, uint8_t *out)
{
	return 0;
}

void cr_bcphr_encrypt_finalize(struct cr_bcphr_s *cipher, uint8_t *out)
{
}

ssize_t cr_bcphr_decrypt_finalize(struct cr_bcphr_s *cipher, uint8_t *out)
{
	return -1;
}

struct cr_bcphr_s *cr_bcphr_des(const uint8_t *key, enum cr_bcphr_mode mode)
{
    return NULL;
}

struct cr_bcphr_s *cr_bcphr_tdea(const uint8_t *key, enum cr_bcphr_mode mode)
{
    return NULL;
}
