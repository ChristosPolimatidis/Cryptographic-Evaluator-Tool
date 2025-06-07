import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class TripleDESExample {
    public static void main(String[] args) throws Exception {
        // Generate a 3DES key
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
        keyGen.init(168); // 3DES key length
        SecretKey secretKey = keyGen.generateKey();

        // Convert key to raw bytes
        byte[] keyBytes = secretKey.getEncoded();
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DESede");

        // Create cipher instance
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");

        // Encrypt data
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal("SensitiveData".getBytes());
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        // Decrypt data
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
