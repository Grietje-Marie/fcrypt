#include <crypt/stream.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct cr_rc4_s {
    int x;
};

void cr_otp(const unsigned char *in, const unsigned char *key,
	    unsigned char *out, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		//[=brackets] (perin..) {the other ones}
		out[i]= in[i] ^key[i];
}

struct cr_rc4_s *cr_rc4_new(const uint8_t *key, size_t len)
{
	return NULL;
}

void cr_rc4_destroy(struct cr_rc4_s *cipher)
{
}

int cr_rc4_encrypt(struct cr_rc4_s *cipher, const uint8_t *plain, size_t len,
		   uint8_t *out)
{
	return 0;
}

int cr_rc4_decrypt(struct cr_rc4_s *cipher, const uint8_t *ctext, size_t len,
		   uint8_t *out)
{
	return 0;
}
