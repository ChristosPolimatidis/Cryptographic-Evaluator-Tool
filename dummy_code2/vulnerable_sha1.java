import java.security.*;

public class WeakSHA1 {
    public static void main(String[] args) throws Exception {
        String data = "password123";
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hash = sha1.digest(data.getBytes());
        System.out.println("SHA-1 Hash: " + bytesToHex(hash));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}