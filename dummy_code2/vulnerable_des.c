#include <openssl/des.h>
#include <stdio.h>
#include <string.h>

void weak_encrypt(const char *plaintext, unsigned char *key, unsigned char *ciphertext) {
    DES_key_schedule ks;
    DES_set_key((DES_cblock *)key, &ks);
    DES_ecb_encrypt((DES_cblock *)plaintext, (DES_cblock *)ciphertext, &ks, DES_ENCRYPT);
}

void weak_decrypt(unsigned char *ciphertext, unsigned char *key, char *decrypted) {
    DES_key_schedule ks;
    DES_set_key((DES_cblock *)key, &ks);
    DES_ecb_encrypt((DES_cblock *)ciphertext, (DES_cblock *)decrypted, &ks, DES_DECRYPT);
}

int main() {
    unsigned char key[8] = "weak_key";
    unsigned char plaintext[8] = "secret12";
    unsigned char encrypted[8], decrypted[8];

    weak_encrypt(plaintext, key, encrypted);
    weak_decrypt(encrypted, key, decrypted);

    printf("Encrypted: %s\\n", encrypted);
    printf("Decrypted: %s\\n", decrypted);

    return 0;
}