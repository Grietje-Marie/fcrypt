#include <crypt/stream.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct cr_rc4_s {
	uint8_t S[256];
	int i;
	int j;
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
	struct cr_rc4_s *p;

	p = malloc(sizeof(struct cr_rc4_s));
	if (p == NULL) return NULL;

	p->i = 0;
	p-> j = 0;

	for(int i = 0; i < 256; i++){
		p->S[i] = i;
	}
	int j = 0;
	for (int i = 0; i < 256; i++){
		
		j = (j+ p->S[i] + key[i % len]) % 256;
		uint8_t swap = p->S[i];
		p->S[i] = p->S[j];
		p->S[j] = swap;
	}
	


	return p;
}

void cr_rc4_destroy(struct cr_rc4_s *cipher)
{
	free(cipher);
}

uint8_t cr_rc4_byte(struct cr_rc4_s*cipher)
{
	cipher->i = (cipher->i + 1 )% 256; 
	cipher->j = (cipher->j + cipher->S[cipher->i]) % 256; 
	uint8_t swap = cipher->S[cipher->i];
	cipher->S[cipher->i] = cipher->S[cipher->j];
	cipher->S[cipher->j] = swap;
	uint8_t t = (cipher->S[cipher->i] + cipher->S[cipher->j]) % 256;

	return cipher->S[t];
}

int cr_rc4_encrypt(struct cr_rc4_s *cipher, const uint8_t *plain, size_t len,
		   uint8_t *out)
{
	for(size_t i = 0 ; i < len; i++){

		out[i] = cr_rc4_byte(cipher) ^ plain[i];
	} 
	return 0;
}

int cr_rc4_decrypt(struct cr_rc4_s *cipher, const uint8_t *ctext, size_t len,
		   uint8_t *out)
{
	for(size_t i = 0; i < len; i++){

		out[i] = cr_rc4_byte(cipher) ^ ctext[i];
	}	
	return 0;
}
