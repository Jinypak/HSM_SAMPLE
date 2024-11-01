import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;
import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;

/**
 * This class demonstrates how to unwrap an exported wrapped RSA private key using an existing AES key in the HSM.
 */
public class HSMUnWrappingTEST {

    static public void println(String s) {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage() {
        println("java HSMUnwrappingTEST -slot <slotId> -password <password> -file <fileName>\n");
        println("");
        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args) {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String password = ""; // 파티션 패스워드
        String wrappedKeyFileName = "wrapped_rsa_private_key.bin";
        boolean bPrivate = false;

        // 명령줄 인자 처리
        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-slot")) {
                if (++i >= args.length) usage();
                slotId = Integer.parseInt(args[i]);
            } else if (args[i].equalsIgnoreCase("-password")) {
                if (++i >= args.length) usage();
                password = args[i];
            } else if (args[i].equalsIgnoreCase("-file")) {
                if (++i >= args.length) usage();
                wrappedKeyFileName = args[i];
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
            println("3. Logging in to the session");
            if (password.length() > 0) {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());
                bPrivate = true;
            }
            println("Login successful.");

            // AES 키 찾기
            println("4. Find existing AES key");
            // TEST KEY LABEL : AES Wrapping Key
            CK_OBJECT_HANDLE hAesKey = findKey(session, "AES Wrapping Key", CKK.AES, bPrivate);
            if (!hAesKey.isValidHandle()) {
                println("AES key not found. Exiting.");
                return;
            }
            println("AES Key found with handle: " + hAesKey.longValue());

            // 외부 파일에서 래핑된 키 읽기
            println("5. Reading wrapped key from file: " + wrappedKeyFileName);
            byte[] wrappedKey = readWrappedKeyFromFile(wrappedKeyFileName);
            if (wrappedKey == null) {
                println("Failed to read wrapped key. Exiting.");
                return;
            }
            println("Wrapped key read successfully. Length: " + wrappedKey.length);

            // IV 값 입력, Wrapping 샘플 코드 참조
            Scanner scanner = new Scanner(System.in);
            println("Enter the IV (Initialization Vector) in hexadecimal format (e.g., 01234567):");
            String ivHexString = scanner.nextLine().trim();
            byte[] iv = hexStringToByteArray(ivHexString);

            // IV가 유효한지 확인
            if (iv == null || iv.length != 4) {
                println("Invalid IV length. IV must be 4 bytes in hexadecimal format.");
                return;
            }
            println("6. Using IV for Unwrapping: " + ivHexString);

            CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_KWP, iv);

            // ***********************
            //   UNWRAPPING
            // ***********************
            println("7. Unwrapping the RSA Private Key with AES Key");
            CK_OBJECT_HANDLE hUnwrappedKey = new CK_OBJECT_HANDLE();
            CK_ATTRIBUTE[] rsaPrivateTemplate = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.PRIVATE_KEY),
                new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.RSA),
                new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
                // Unwrapping 후 LABEL : Unwrapped RSA Private Key TEST
                new CK_ATTRIBUTE(CKA.LABEL, "Unwrapped RSA Private Key TEST".getBytes()),
                new CK_ATTRIBUTE(CKA.PRIVATE, new CK_BBOOL(bPrivate)),
                new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.DECRYPT, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.UNWRAP, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.EXTRACTABLE, CK_BBOOL.TRUE)
            };

            // 언래핑 작업 수행
            CryptokiEx.C_UnwrapKey(session, mechanism, hAesKey, wrappedKey, wrappedKey.length, rsaPrivateTemplate, rsaPrivateTemplate.length, hUnwrappedKey);

            // 언래핑된 키 확인
            if (!hUnwrappedKey.isValidHandle()) {
                println("Failed to unwrap the RSA Private Key.");
                return;
            }
            println("8. RSA Private Key successfully unwrapped with handle: " + hUnwrappedKey.longValue());

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
     * HSM에서 기존 키를 찾습니다.
     *
     * @param session 열린 세션의 핸들
     * @param keyLabel 찾을 키의 라벨
     * @param keyType 키의 유형
     * @return 찾은 키의 핸들
     */
    static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session,
                                    String keyName,
                                    CK_KEY_TYPE keyType,
                                    boolean bPrivate)
    {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};

        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        /* setup the template of the object to search for */
        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  keyType),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes()),
            new CK_ATTRIBUTE(CKA.PRIVATE,   new CK_BBOOL(bPrivate))
        };

        CryptokiEx.C_FindObjectsInit(session, template, template.length);

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1)
        {
            /* return the handle of the located object */
            return hObjects[0];
        }
        else
        {
            /* return an object handle which is invalid */
            return new CK_OBJECT_HANDLE();
        }
    }

    /**
     * 외부 파일에서 래핑된 키를 읽어옵니다.
     *
     * @param fileName 읽어올 파일의 이름
     * @return 파일에서 읽은 래핑된 키 바이트 배열
     */
    static byte[] readWrappedKeyFromFile(String fileName) {
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] wrappedKey = new byte[fis.available()];
            fis.read(wrappedKey);
            return wrappedKey;
        } catch (IOException e) {
            println("Failed to read wrapped key from file: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 16진수 문자열을 바이트 배열로 변환합니다.
     *
     * @param hexString 변환할 16진수 문자열
     * @return 변환된 바이트 배열
     */
    static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                 + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }
}
