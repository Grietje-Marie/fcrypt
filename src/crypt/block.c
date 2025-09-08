#include <crypt/des.h>
#include <crypt/rand.h>
#include <crypt/block.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cr_bcphr_s {
    int x;
};

struct cr_bcphr_s *cr_bcphr_new(const uint8_t *key,
				size_t keysz,
				size_t blksz,
				blkencrypt_t encrypt,
				blkdecrypt_t decrypt, enum cr_bcphr_mode mode)
{
	return NULL;
}

void cr_bcphr_destroy(struct cr_bcphr_s *cipher)
{
}

size_t cr_bcphr_block_size(const struct cr_bcphr_s *cipher)
{
	return 0;
}

void cr_bcphr_set_iv(struct cr_bcphr_s *cipher, const uint8_t *iv)
{
}

size_t cr_bcphr_get_iv(const struct cr_bcphr_s *cipher, uint8_t *iv)
{
	return 0;
}

enum cr_bcphr_mode cr_bcphr_get_mode(const struct cr_bcphr_s *cipher)
{
	return 0;
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
