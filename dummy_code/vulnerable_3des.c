#include <openssl/des.h>
#include <stdio.h>
#include <string.h>

int main() {
    // 3DES key and initialization vector
    DES_cblock key1, key2, key3, ivec;
    DES_key_schedule ks1, ks2, ks3;

    // Set key values (dummy keys)
    DES_string_to_key("12345678", &key1);
    DES_string_to_key("abcdefgh", &key2);
    DES_string_to_key("ijklmnop", &key3);
    DES_set_key_checked(&key1, &ks1);
    DES_set_key_checked(&key2, &ks2);
    DES_set_key_checked(&key3, &ks3);

    // Plaintext and encrypted text buffers
    char plaintext[] = "SensitiveData!";
    char ciphertext[32];
    char decrypted[32];

    // Encrypt using 3DES
    DES_ede3_cbc_encrypt((unsigned char *)plaintext, (unsigned char *)ciphertext, strlen(plaintext) + 1,
                          &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);

    printf("Encrypted: %s\n", ciphertext);

    // Decrypt
    DES_ede3_cbc_encrypt((unsigned char *)ciphertext, (unsigned char *)decrypted, strlen(plaintext) + 1,
                          &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

    printf("Decrypted: %s\n", decrypted);

    return 0;
}
