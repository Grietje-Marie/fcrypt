#include <getopt.h>
#include <stdlib.h>


#define HELP_FMT                                                               \
  "Usage: %s [options]\n\n"                                                    \
  "Options:\n"                                                                 \
  "  -m <mode>, --mode <mode>\n"                                               \
  "       The cipher operation mode for block ciphers: ecb, cbc, cfb,\n"       \
  "       ofb. (default: cbc)\n"                                               \
  "  -c <cipher>, --cipher <cipher>\n"                                         \
  "       The cipher to use: otp, rc4, des, tdea. (required)\n"                \
  "  -d, --decrypt\n"                                                          \
  "       Run in decryption mode.\n"                                           \
  "  -i <file>, --in <file>\n"                                                 \
  "       The file to encrypt or decrypt. (required)\n"                        \
  "  -o <file>, --out <file>\n"                                                \
  "       The file which will contain the encryption/decryption output.\n"     \
  "       (required)\n"                                                        \
  "  -k <file>, --key <file>\n"                                                \
  "       In encryption, it is the file which will contain a randomly\n"       \
  "       generated key. In decryption, it is the file from which the\n"       \
  "       key will be read. For rc4, this value will be used as a key.\n"      \
  "       (required)\n"                                                        \
  "  -h, --help\n"                                                             \
  "       Display this help and exit\n"

static struct option cli_options[] = {
	{"mode", required_argument, 0, 'm'},
	{"cipher", required_argument, 0, 'c'},
	{"decrypt", no_argument, 0, 'd'},
	{"in", required_argument, 0, 'i'},
	{"out", required_argument, 0, 'o'},
	{"key", required_argument, 0, 'k'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

int fcrypt_main(int argc, char **argv)
{
	return EXIT_FAILURE;
}
