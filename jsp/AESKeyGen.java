import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import com.safenetinc.luna.provider.LunaProvider;
import com.safenetinc.luna.provider.key.LunaKey;

import java.util.Scanner;

public class AESKeyGen {

    public static void println(String s) {
      System.out.println(s);
    }

    // Configure these as required.
    private static final int slot = 0;
    public static final String provider = "LunaProvider";
    public static final String keystoreProvider = "Luna";
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static void main(String[] args) {

        KeyStore myStore = null;
        String passwd = null;
        
        Scanner scanner = new Scanner(System.in);
        try {

            Security.addProvider(new LunaProvider());
            ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
            myStore = KeyStore.getInstance("Luna");
            println("AES 샘플 키를 생성하는 과정입니다.");
            println("PIN을 입력하세요 :");
            passwd = scanner.nextLine(); // 입력값을 String으로 받음

            myStore.load(is1, passwd.toCharArray());
        } catch (KeyStoreException kse) {
            println("Unable to create keystore object");
            System.exit(-1);
        } catch (NoSuchAlgorithmException nsae) {
            println("Unexpected NoSuchAlgorithmException while loading keystore");
            System.exit(-1);
        } catch (CertificateException e) {
            println("Unexpected CertificateException while loading keystore");
            System.exit(-1);
        } catch (IOException e) {
            // this should never happen
            println("Unexpected IOException while loading keystore.");
            System.exit(-1);
        }
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES", provider);

            boolean valid = false;
            int keyLength = 0;
            while (!valid) {
                try {
                    // 키 길이 입력
                    println("Key 길이를 입력하세요 :");
                    keyLength = Integer.parseInt(scanner.nextLine());
                    valid = true;  // 변환에 성공하면 루프 종료
                } catch (NumberFormatException e) {
                    System.out.print("유효한 정수 값을 입력하세요 :");  // 잘못된 입력 시 다시 요청
                }
            }
            kg.init(keyLength);
            LunaKey key = (LunaKey) kg.generateKey();
            println("Key의 라벨을 입력하세요 :");
            
            String keyLabelString = scanner.nextLine();
            myStore.setKeyEntry(keyLabelString, key, null, null);
            System.out.println("키가 생성되었습니다. Key Label :" + keyLabelString);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            // Scanner 객체를 닫아줌
            scanner.close();
        }
    }
}
