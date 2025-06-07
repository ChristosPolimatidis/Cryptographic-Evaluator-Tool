import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AES128Encryption {
    public static String encryptAES128(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decryptAES128(String encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);  // AES-128 key size
        SecretKey key = keyGen.generateKey();
        
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];  // 16-byte IV for AES
        random.nextBytes(iv);

        String data = "LowRiskAES128";
        String encrypted = encryptAES128(data, key, iv);
        String decrypted = decryptAES128(encrypted, key, iv);

        System.out.println("Encrypted AES-128 Data: " + encrypted);
        System.out.println("Decrypted AES-128 Data: " + decrypted);
    }
}
