#include <crypt/des.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

const size_t des_blksz = 8;
const size_t tdea_blksz = 8;
const size_t des_keysz = 8;
const size_t tdea_keysz = 24;

#define GET_BIT(array, bit)                     \
    (array[bit/8] & (0x80 >> (bit%8)))

#define SET_BIT(array, bit)                     \
    (array[bit/8] |= (0x80 >> (bit%8)))

#define CLEAR_BIT(array, bit)                   \
    (array[bit/8] &= ~(0x80 >> (bit%8)))

static const int ip_table[] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

static const int fp_table[] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
};

static const int expansion_table[] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

static const int sbox[8][64] = {
	{14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
	 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
	 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
	 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13},
	{15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
	 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
	 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
	 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9},
	{10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
	 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
	 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
	 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12},
	{7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
	 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
	 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
	 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14},
	{2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
	 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
	 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
	 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3},
	{12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
	 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
	 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
	 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13},
	{4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
	 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
	 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
	 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12},
	{13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
	 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
	 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
	 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11}
};

static const int p_table[] = {
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23,
	26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27,
	3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

static const int pc1_table[] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3,
	60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15, 7,
	62, 54, 46, 38, 30, 22, 14, 6,
	61, 53, 45, 37, 29, 21, 13, 5,
	28, 20, 12, 4
};

static const int pc2_table[] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

static void permute(const uint8_t *in, uint8_t *out, const int *p, size_t len){
	for (uint8_t i = 0; i < len; i++){
		int index = p[i] - 1;
		GET_BIT(in, index); //gets the bit-value in position index from in 
		if (GET_BIT(in, index)) //condition that checks if the value is 1 (T) or 0(F)
		{
			SET_BIT(out, i); //out = set bit; i = index of bits

		}
		else{
			CLEAR_BIT(out, i);
		};

	};
};

static void left_rotate(uint8_t *key) //static means that it is not exported 
{
	int llsb, rlsb;

	llsb = (key[0] & 0x80) >> 3;
	rlsb = (key[3] & 0x08) >> 3;

	key[0] = (key[0] << 1) | ((key[1] & 0x80) >> 7);
	key[1] = (key[1] << 1) | ((key[2] & 0x80) >> 7);
	key[2] = (key[2] << 1) | ((key[3] & 0x80) >> 7);

	key[3] = (((key[3] << 1) | ((key[4] & 0x80) >> 7)) & ~0x10) | llsb;

	key[4] = (key[4] << 1) | ((key[5] & 0x80) >> 7);
	key[5] = (key[5] << 1) | ((key[6] & 0x80) >> 7);
	key[6] = (key[6] << 1) | rlsb;
}


//function generating key schedule:
static void key_scheduling (const uint8_t *key, uint8_t genAry[16][6]){ //keyL <-- poinnter key; genAry(stores our 16 keys)
	uint8_t storage[7]; 
	permute(key, storage, pc1_table, 56);
	for(int i = 0; i <16; i++){
		left_rotate(storage);
		if (i !=0 && i != 1 && i != 8 && i != 15)
		{left_rotate(storage);}
		permute(storage, genAry[i], pc2_table, 48);
		
	}
};

void cr_des_structure(const uint8_t *plain, const uint8_t genAry[16][6],  uint8_t *out)
{
	uint8_t Arrayy[8];
	uint8_t sblock [4];
	uint8_t pblock [4], rblock[8]; 

	permute(plain, Arrayy, ip_table, 64);	
	for(int n = 0; n < 16; n++){
		uint8_t eblock [6];
		permute (Arrayy + 4, eblock, expansion_table, 48 );
		for(int i = 0; i < 6; i++){
			eblock [i] ^= genAry [n][i];
		}

		sblock[0] = sbox[0][(eblock[0] & 0xfc) >> 2] << 4;
		sblock[0] |=
		    sbox[1][(eblock[0] & 0x03) << 4 | (eblock[1] & 0xf0) >> 4];

		sblock[1] =
		    sbox[2][(eblock[1] & 0x0f) << 2 | (eblock[2] & 0xc0) >> 6]
		    << 4;
		sblock[1] |= sbox[3][eblock[2] & 0x3f];

		sblock[2] = sbox[4][(eblock[3] & 0xfc) >> 2] << 4;
		sblock[2] |=
		    sbox[5][(eblock[3] & 0x03) << 4 | (eblock[4] & 0xf0) >> 4];

		sblock[3] =
		    sbox[6][(eblock[4] & 0x0f) << 2 | (eblock[5] & 0xc0) >> 6]
		    << 4;
		sblock[3] |= sbox[7][eblock[5] & 0x3f];

		permute (sblock, pblock, p_table, 32);
		
		memcpy(rblock, Arrayy + 4, 4);
		for(int i = 0; i < 4; i++)
			rblock [4 + i] = Arrayy[i] ^pblock[i];
		memcpy(Arrayy, rblock, 8);
	}

	memcpy(rblock, Arrayy + 4, 4);
	memcpy(rblock + 4,  Arrayy, 4);

	permute(rblock,out,fp_table,64);
}


void cr_des_encrypt(const uint8_t *plain, const uint8_t *key, uint8_t *out)
{
	uint8_t genAry[16][6];
	key_scheduling(key, genAry);
	cr_des_structure(plain, genAry, out);
}

void cr_des_decrypt(const uint8_t *ctext, const uint8_t *key, uint8_t *out)
{
	uint8_t genAry[16][6];
	uint8_t swap[6];
	key_scheduling(key, genAry);
	
	for (int i = 0; i < 8; i++) {
		memcpy(swap, genAry[i], 6);
		memcpy(genAry[i], genAry[15 - i], 6);
		memcpy(genAry[15-i], swap, 6);
	}

	cr_des_structure(ctext, genAry, out);
}

void cr_tdea_encrypt(const uint8_t *plain, const uint8_t *key, uint8_t *out)
{
	uint8_t enc[tdea_blksz];
	uint8_t dec[tdea_blksz];

	cr_des_encrypt(plain, key, enc);
	cr_des_decrypt(enc,key+8,dec);
	cr_des_encrypt(dec,key+16,out);
}

void cr_tdea_decrypt(const uint8_t *ctext, const uint8_t *key, uint8_t *out)
{
	uint8_t enc[tdea_blksz];
	uint8_t dec[tdea_blksz];
	cr_des_decrypt(ctext,key+16,dec);
	cr_des_encrypt(dec,key+8,enc);
	cr_des_decrypt(enc,key,out);
}
