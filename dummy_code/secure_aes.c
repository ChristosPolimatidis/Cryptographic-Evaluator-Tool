// 3. C Script - Secure AES Encryption
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void secure_encrypt(const unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

int main()
{
    unsigned char key[32] = "thisisaverysecurekeythatweuse123";
    unsigned char iv[16] = "thisisanIVvector";
    unsigned char plaintext[] = "securedata";
    unsigned char encrypted[128];

    secure_encrypt(plaintext, key, iv, encrypted);
    printf("Encrypted Data: %s\\n", encrypted);

    return 0;
}