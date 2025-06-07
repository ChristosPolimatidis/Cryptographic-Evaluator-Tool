#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>

int main() {
    RSA *key = RSA_generate_key(1024, RSA_F4, NULL, NULL); // 🔴 Weak RSA Key (1024-bit)

    FILE *priv_file = fopen("vulnerable_rsa_private.pem", "wb");
    PEM_write_RSAPrivateKey(priv_file, key, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);

    FILE *pub_file = fopen("vulnerable_rsa_public.pem", "wb");
    PEM_write_RSA_PUBKEY(pub_file, key);
    fclose(pub_file);

    RSA_free(key);
    printf("Generated Vulnerable RSA 1024-bit Key\\n");
    return 0;
}
