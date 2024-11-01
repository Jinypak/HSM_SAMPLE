import com.safenetinc.luna.provider.LunaProvider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;

public class InsertAESKWP {

    private static final int slot = 0;
    private static final String passwd = "Apko8085!";
    private static final String aesKeyAlias = "AES-KMP-01"; // 삽입할 AES256-KWP 키의 별칭
    private static final String keyFilePath = "extracted_aes256kwp_key.bin"; // 저장된 AES 키 파일 경로

    public static void main(String[] args) {
        KeyStore myKeyStore = null;
        SecretKey aesKWPKey = null;

        try {
            System.out.println("Step 1: Initializing KeyStore and Security Provider...");
            Security.addProvider(new LunaProvider());
            ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
            myKeyStore = KeyStore.getInstance("Luna");
            myKeyStore.load(is1, passwd.toCharArray());
            System.out.println("Step 1: KeyStore and Security Provider initialization completed.");

            // AES256-KWP 키 파일에서 로드
            System.out.println("Step 2: Loading AES256-KWP Key from file...");
            byte[] keyBytes = loadKeyFromFile(keyFilePath);

            if (keyBytes != null) {
                // SecretKey 객체로 변환
                aesKWPKey = new SecretKeySpec(keyBytes, "AES");
                System.out.println("Step 2: AES256-KWP Key loaded and converted successfully.");

                // 키스토어에 AES 키 삽입
                System.out.println("Step 3: Inserting AES256-KWP Key into KeyStore...");
                myKeyStore.setKeyEntry(aesKeyAlias, aesKWPKey, passwd.toCharArray(), null);
                System.out.println("Step 3: AES256-KWP Key inserted into KeyStore successfully.");
            } else {
                System.out.println("Failed to load AES256-KWP Key from file.");
            }

        } catch (Exception e) {
            System.out.println("Exception occurred during KeyStore initialization or key insertion.");
            e.printStackTrace();
        }
    }

    // 파일에서 키를 로드하는 메소드
    private static byte[] loadKeyFromFile(String filePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] data = new byte[fis.available()];
            fis.read(data);
            return data;
        }
    }
}
