// 4. Java Script - Secure SHA-256 Hashing
import java.security.*;

public class SecureSHA256 {
    public static void main(String[] args) throws Exception {
        String data = "password123";
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(data.getBytes());
        System.out.println("SHA-256 Hash: " + bytesToHex(hash));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}