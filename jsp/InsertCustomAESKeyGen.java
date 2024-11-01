import com.safenetinc.luna.provider.LunaProvider;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;

public class InsertCustomAESKeyGen {

    private static final int slot = 0;
    private static final String passwd = "Apko8085!";
    private static final String aesKeyAlias = "AES_KWP_02"; // HSM에 삽입할 AES 키의 별칭

    public static void main(String[] args) {
        KeyStore myKeyStore = null;

        // 사용자가 지정한 AES 키 값 (예: 256 비트 키)
        byte[] customAESKeyValue = new byte[] {
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, 
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, 
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, 
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, 
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
        };

        try {
            System.out.println("Step 1: Initializing KeyStore and Security Provider...");
            Security.addProvider(new LunaProvider());
            ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
            myKeyStore = KeyStore.getInstance("Luna");
            myKeyStore.load(is1, passwd.toCharArray());
            System.out.println("Step 1: KeyStore and Security Provider initialization completed.");

            // 지정한 값을 사용하여 AES 키 생성
            System.out.println("Step 2: Creating AES Key using specified value...");
            SecretKey customAESKey = new SecretKeySpec(customAESKeyValue, "AES");
            System.out.println("Step 2: AES Key created successfully with specified value.");

            // 키스토어에 AES 키 삽입
            System.out.println("Step 3: Inserting AES Key into KeyStore...");
            myKeyStore.setKeyEntry(aesKeyAlias, customAESKey, passwd.toCharArray(), null);
            System.out.println("Step 3: AES Key inserted into KeyStore successfully.");

        } catch (Exception e) {
            System.out.println("Exception occurred during KeyStore initialization or key insertion.");
            e.printStackTrace();
        }
    }
}
