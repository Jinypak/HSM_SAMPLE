import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Random;
import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;


public class HSMWrappingTEST {

    static public void println(String s) {
        System.out.println(s);
    }

    public static void usage() {
        println("java ...HSMWrappingTest -slot <slotId> -password <password>\n");
        println("");
        System.exit(1);
    }

    // IV
    private static byte[] iv = null;


    public static void main(String[] args) {


        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String password = ""; // 파티션 패스워드
        boolean bPrivate = false;

        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-slot")) {
                if (++i >= args.length) usage();
                slotId = Integer.parseInt(args[i]);
            } else if (args[i].equalsIgnoreCase("-password")) {
                if (++i >= args.length) usage();
                password = args[i];
            } else {
                usage();
            }
        }

        try {
            // Cryptoki 라이브러리 초기화
            println("1. Initializing Cryptoki");
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

            // 세션 열기
            println("2. Opening session");
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

            // 세션 로그인
            println("3. Log in to the session");
            if (password.length() > 0) {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());
                bPrivate = true;
            }
            println("Login successful.");

            // AES 키 생성
            println("4. Generating AES key");
            CK_OBJECT_HANDLE hAesKey = generateAESKey(session);
            if (!hAesKey.isValidHandle()) {
                println("Failed to generate AES key.");
                return;
            }
            println("AES Key generated with handle: " + hAesKey.longValue());

            // RSA 키 쌍 생성
            println("5. Generating RSA key pair");
            CK_OBJECT_HANDLE hRsaPrivateKey = new CK_OBJECT_HANDLE();
            CK_OBJECT_HANDLE hRsaPublicKey = new CK_OBJECT_HANDLE();
            generateRSAKeyPair(session, "RSA Key", bPrivate, hRsaPublicKey, hRsaPrivateKey);
            if (!hRsaPrivateKey.isValidHandle()) {
                println("Failed to generate RSA Private Key.");
                return;
            }
            println("RSA Key Pair generated with Public Key handle: " + hRsaPublicKey.longValue() + ", Private Key handle: " + hRsaPrivateKey.longValue());

            // AES-KWP 메커니즘 설정
            iv = new byte[4];  // AES-KWP IV
            new Random().nextBytes(iv);

            StringBuilder hexString = new StringBuilder();
            for (byte b : iv) {
                hexString.append(String.format("%02X", b));
            }
            String ivHexString = hexString.toString();
            System.out.println("6. Generated IV: " + ivHexString);
            CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_KWP, iv);

            // ***********************
            //   WRAPPING
            // ***********************
            println("7. Wrapping RSA Private Key with AES Key");
            LongRef wrappedKeyLength = new LongRef();
            CryptokiEx.C_WrapKey(session, mechanism, hAesKey, hRsaPrivateKey, null, wrappedKeyLength);
            byte[] wrappedKey = new byte[(int) wrappedKeyLength.value];
            CryptokiEx.C_WrapKey(session, mechanism, hAesKey, hRsaPrivateKey, wrappedKey, wrappedKeyLength);
            println("RSA Private Key successfully wrapped. Wrapped key length: " + wrappedKeyLength.value);

            // ***********************
            //   EXTERNAL EXPORT
            // ***********************
            String wrappedKeyFileName = "wrapped_rsa_private_key.bin";
            println("8. Exporting the wrapped key to external file: " + wrappedKeyFileName);
            exportWrappedKeyToFile(wrappedKey, wrappedKeyFileName);
            println("Wrapped key successfully exported.");

        } catch (CKR_Exception ex) {
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            // 세션 종료 및 정리
            try {
                println("9.Log out and Closing Session");
                Cryptoki.C_Logout(session);
                Cryptoki.C_CloseSession(session);
                println("Finalizing Cryptoki");
                Cryptoki.C_Finalize(null);
                println("Quit process");
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    /**
     * AES 키를 생성합니다.
     *
     * @param session 열린 세션의 핸들
     * @return 생성된 AES 키의 핸들
     */
    static CK_OBJECT_HANDLE generateAESKey(CK_SESSION_HANDLE session) {
        CK_OBJECT_HANDLE hAesKey = new CK_OBJECT_HANDLE();
        CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.AES_KEY_GEN);
        CK_ATTRIBUTE[] aesTemplate = {
            new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.AES),
            new CK_ATTRIBUTE(CKA.VALUE_LEN, 32), // 256-bit AES 키
            new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL, "AES Wrapping Key".getBytes()),
            new CK_ATTRIBUTE(CKA.PRIVATE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.TRUE)
        };
        try {
            CryptokiEx.C_GenerateKey(session, keyGenMech, aesTemplate, aesTemplate.length, hAesKey);
        } catch (CKR_Exception ex) {
            println("Error generating AES key: " + ex.getMessage());
            ex.printStackTrace();
        }
        return hAesKey;
    }

    /**
     * RSA 키 쌍을 생성합니다.
     *
     * @param session 열린 세션의 핸들
     * @param keyName 생성할 키의 이름
     * @param bPrivate 개인 키가 비공개 객체인지 여부
     * @param hPublicKey 생성된 공개 키의 핸들
     * @param hPrivateKey 생성된 개인 키의 핸들
     */
    static void generateRSAKeyPair(CK_SESSION_HANDLE session, String keyName, boolean bPrivate,
                                   CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey) {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.RSA_PKCS_KEY_PAIR_GEN);
        byte[] pubExponent = {0x01, 0x00, 0x01};
        Long modulusBits = 2048L;

        CK_ATTRIBUTE[] publicTemplate = {
            new CK_ATTRIBUTE(CKA.CLASS, CKO.PUBLIC_KEY),
            new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.RSA),
            new CK_ATTRIBUTE(CKA.LABEL, (keyName + " Public").getBytes()),  // 공개 키 라벨
            new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.MODULUS_BITS, modulusBits),
            new CK_ATTRIBUTE(CKA.PUBLIC_EXPONENT, pubExponent),
            new CK_ATTRIBUTE(CKA.ENCRYPT, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.VERIFY, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.WRAP, CK_BBOOL.TRUE)
        };

        CK_ATTRIBUTE[] privateTemplate = {
            new CK_ATTRIBUTE(CKA.CLASS, CKO.PRIVATE_KEY),
            new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.RSA),
            new CK_ATTRIBUTE(CKA.LABEL, (keyName + " Private").getBytes()),  // 개인 키 라벨
            new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate)),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.TRUE)
        };

        try {
            CryptokiEx.C_GenerateKeyPair(session, keyGenMech,
                                         publicTemplate, publicTemplate.length,
                                         privateTemplate, privateTemplate.length,
                                         hPublicKey, hPrivateKey);
        } catch (CKR_Exception ex) {
            println("Error generating RSA key pair: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    /**
     * 래핑된 키를 외부 파일로 내보냅니다.
     *
     * @param wrappedKey 래핑된 키 바이트 배열
     * @param fileName 저장할 파일 이름
     */
    static void exportWrappedKeyToFile(byte[] wrappedKey, String fileName) {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(wrappedKey);
            println("Wrapped key exported to " + fileName);
        } catch (IOException e) {
            println("Failed to export wrapped key: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
