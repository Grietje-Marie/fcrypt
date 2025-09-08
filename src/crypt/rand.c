#include <crypt/rand.h>
#include <stdio.h>

int cr_rand_bytes(unsigned char *buf, size_t len)
{
    FILE *Datei;
    Datei = fopen ("/dev/urandom", "rb");
    if(Datei == NULL){
        return -1;
    }

    if(fread(buf,1,len,Datei) != len){
        fclose(Datei);
        return -1;
    }

    fclose(Datei);
    return 0;
}
