#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>

int main() {
    RSA *key = RSA_generate_key(2048, RSA_F4, NULL, NULL); // 🟢 Secure RSA Key (2048-bit)

    FILE *priv_file = fopen("secure_rsa_private.pem", "wb");
    PEM_write_RSAPrivateKey(priv_file, key, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);

    FILE *pub_file = fopen("secure_rsa_public.pem", "wb");
    PEM_write_RSA_PUBKEY(pub_file, key);
    fclose(pub_file);

    RSA_free(key);
    printf("Generated Secure RSA 2048-bit Key\\n");
    return 0;
}
