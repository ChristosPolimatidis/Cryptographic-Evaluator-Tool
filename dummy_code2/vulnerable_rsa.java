import java.security.*;
import javax.crypto.*;

public class WeakRSA {
    public static void main(String[] args) throws Exception {
        String data = "secret";
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024); // Weak key size
        KeyPair pair = keyGen.generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        byte[] encrypted = cipher.doFinal(data.getBytes());
        System.out.println("Encrypted: " + bytesToHex(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}