/*
  This file is used to demonstrate how to interface to SafeNet's
  licensed development product. You have a royalty-free right
  to use, modify, reproduce and distribute this demonstration
  file (including any modified version), provided that you agree
  that SafeNet has no warranty, implied or otherwise, or liability
  for this demonstration file or any modified version of it.
*/

// change these to the correct values
#define SLOT 0
#define PASSWORD "Apko8085!"

#undef UNICODE

#ifdef OS_WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cryptoki_v2.h"
#include "sha3.h"
#include "smSample.h"
#include "3gpp.h"

#define PLAIN_SZ 512

#ifdef OS_WIN32
HINSTANCE LibHandle = 0;
#else
void *LibHandle = NULL;
#endif

#define CIPHERTEXT_FILE "cipherText.bin"
#define SIGNATURE_FILE "signText.bin"

#define CHUNK_SIZE 100
#define CIPHERTEXT_BUF_SZ 256

CK_FUNCTION_LIST *P11Functions = NULL;
CK_SFNT_CA_FUNCTION_LIST *SfntFunctions = NULL;

CK_OBJECT_HANDLE hSymKey = 0;
CK_BYTE PlainText[PLAIN_SZ];
CK_BYTE *P_EncText = NULL;
CK_ULONG EncSz = 0;
CK_BYTE *P_DecText = NULL;
CK_ULONG PlainSz = 0;

char LibPath[4096];

/*
    FUNCTION:        CK_BBOOL GetLibrary()
*/
CK_BBOOL GetLibrary()
{
    CK_BBOOL myRC = CK_FALSE;
    char *pPath = NULL;

    pPath = getenv("SfntLibPath");
    if (pPath == NULL)
    {
        printf("Failed to get \"SfntLibPath\"\n");
        printf("Please specify an environment variable named \"SfntLibPath\" that points to\n");
        printf("the full path of the SafeNet cryptoki library.\n");
        return CK_FALSE;
    }

    memset(LibPath, 0, sizeof(LibPath));
    strncpy(LibPath, pPath, sizeof(LibPath));

    myRC = CK_TRUE;

    return myRC;
}

/*
    FUNCTION:        CK_BBOOL LoadP11Functions()
*/
CK_BBOOL LoadP11Functions()
{
    CK_BBOOL myRC = CK_FALSE;
    CK_C_GetFunctionList C_GetFunctionList = NULL;
    CK_RV rv = CKR_TOKEN_NOT_PRESENT;

    if (GetLibrary() == CK_FALSE)
        return CK_FALSE;

#ifdef OS_WIN32
    LibHandle = LoadLibrary(LibPath);
    if (LibHandle)
    {
        C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(LibHandle, "C_GetFunctionList");
    }
    else
    {
        DWORD err = GetLastError();
        char buffer[256];
        memset(buffer, 0, sizeof(buffer));

        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,
                       NULL,
                       err,
                       0,
                       buffer,
                       sizeof(buffer) - 1,
                       NULL);
        printf("LoadLibrary failed: Err: 0x%X, Str: %s\n", err, buffer);
    }
#else
    LibHandle = dlopen(LibPath, RTLD_NOW);
    if (LibHandle)
    {
        C_GetFunctionList = (CK_C_GetFunctionList)dlsym(LibHandle, "C_GetFunctionList");
    }
#endif

    if (!LibHandle)
    {
        printf("failed to load %s\n", LibPath);
    }

    if (C_GetFunctionList)
    {
        rv = C_GetFunctionList(&P11Functions);
    }

    if (P11Functions)
    {
        rv = P11Functions->C_Initialize(NULL_PTR);
    }

    if (rv == CKR_OK)
    {
        myRC = CK_TRUE;
    }

    return myRC;
}

/*
    FUNCTION:        CK_BBOOL LoadSfntExtensionFunctions()
*/
CK_BBOOL LoadSfntExtensionFunctions()
{
    CK_BBOOL myRC = CK_FALSE;
    CK_CA_GetFunctionList CA_GetFunctionList = NULL;
    CK_RV rv = CKR_TOKEN_NOT_PRESENT;
    int iErr = -1;

#ifdef OS_WIN32
    CA_GetFunctionList = (CK_CA_GetFunctionList)GetProcAddress(LibHandle, "CA_GetFunctionList");
#else
    CA_GetFunctionList = (CK_CA_GetFunctionList)dlsym(LibHandle, "CA_GetFunctionList");
#endif

    if (CA_GetFunctionList)
    {
        rv = CA_GetFunctionList(&SfntFunctions);
    }

    if (SfntFunctions)
    {
        myRC = CK_TRUE;
    }

    return myRC;
}

/*
    FUNCTION:        CK_RV Generate3DESKey( CK_SESSION_HANDLE hSession )
*/
CK_RV GenerateRSAKeyPair(CK_SESSION_HANDLE hSession, const char *label)
{
    printf("GENERATING RSA KEY...");
    CK_RV retCode = CKR_OK;
    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG modulusBits = 2048;
    CK_BBOOL yes = CK_TRUE;
    CK_BYTE pubExp[] = {0x01, 0x00, 0x01};

    char pubLabel[64], privLabel[64];
    snprintf(pubLabel, sizeof(pubLabel), "Public %s", label);
    snprintf(privLabel, sizeof(privLabel), "Private %s", label);

    CK_ATTRIBUTE pubKeyTemplate[] = {
        {CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (void *)pubLabel, (CK_ULONG)strlen(pubLabel)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, &pubExp, sizeof(pubExp)},
        {CKA_ENCRYPT, &yes, sizeof(yes)},
        {CKA_TOKEN, &yes, sizeof(yes)}};

    CK_ATTRIBUTE privKeyTemplate[] = {
        {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (void *)privLabel, (CK_ULONG)strlen(privLabel)},
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_DECRYPT, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_TOKEN, &yes, sizeof(yes)}};

    retCode = P11Functions->C_GenerateKeyPair(hSession, &mech,
                                              pubKeyTemplate, sizeof(pubKeyTemplate) / sizeof(*pubKeyTemplate),
                                              privKeyTemplate, sizeof(privKeyTemplate) / sizeof(*privKeyTemplate),
                                              &hPublicKey, &hPrivateKey);

    printf("COMPLETE");

    return retCode;
}

CK_RV GenerateECDSAKeyPair(CK_SESSION_HANDLE hSession, const char *label)
{
    printf("GENERATING ECDSA KEY...");
    CK_RV retCode = CKR_OK;
    CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_BBOOL yes = CK_TRUE;
    char pubLabel[64], privLabel[64];
    snprintf(pubLabel, sizeof(pubLabel), "Public ECDSA KEY %s", label);
    snprintf(privLabel, sizeof(privLabel), "Private ECDSA KEY %s", label);

    // prime256v1 (NIST P-256)
    CK_BYTE ecParams[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
    CK_ATTRIBUTE pubKeyTemplate[] = {
        {CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (void *)pubLabel, (CK_ULONG)strlen(pubLabel)}, // Casting added
        {CKA_EC_PARAMS, ecParams, sizeof(ecParams)},
        {CKA_VERIFY, &yes, sizeof(yes)},
        {CKA_TOKEN, &yes, sizeof(yes)},
    };

    CK_ATTRIBUTE privKeyTemplate[] = {
        {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (void *)privLabel, (CK_ULONG)strlen(privLabel)}, // Casting added
        {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_TOKEN, &yes, sizeof(yes)},
        {CKA_SIGN, &yes, sizeof(yes)},
    };

    retCode = P11Functions->C_GenerateKeyPair(hSession, &mech,
                                              pubKeyTemplate, sizeof(pubKeyTemplate) / sizeof(*pubKeyTemplate),
                                              privKeyTemplate, sizeof(privKeyTemplate) / sizeof(*privKeyTemplate),
                                              &hPublicKey, &hPrivateKey);

    printf("COMPLETE");
    return retCode;
}

/*
    FUNCTION:        CK_RV DecryptData( CK_SESSION_HANDLE hSession )
*/
CK_RV DecryptData(CK_SESSION_HANDLE hSession)
{
    CK_MECHANISM mech;
    CK_RV rv = CKR_OK;

    mech.mechanism = CKM_DES3_CBC_PAD;
    mech.pParameter = (void *)"12345678"; // 8 byte IV
    mech.ulParameterLen = 8;

    rv = P11Functions->C_DecryptInit(hSession, &mech, hSymKey);
    if (rv != CKR_OK)
        goto doneDec;

    rv = P11Functions->C_Decrypt(hSession, P_EncText, EncSz, NULL, &PlainSz);
    if (rv != CKR_OK)
        goto doneDec;

    P_DecText = (CK_BYTE *)calloc(PlainSz, 1);
    if (P_DecText == NULL)
        goto doneDec;

    rv = P11Functions->C_Decrypt(hSession, P_EncText, EncSz, P_DecText, &PlainSz);
    if (rv != CKR_OK)
        goto doneDec;

doneDec:

    return rv;
}

/*
    FUNCTION:        CK_RV FindCurrentSlotObject( CK_SLOT_ID *pckSlot )
*/

CK_RV FindAllObjects(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    CK_OBJECT_HANDLE objHandles[10]; // Buffer for object handles
    CK_ULONG ulObjectCount;

    rv = P11Functions->C_FindObjectsInit(hSession, NULL, 0);
    if (rv != CKR_OK)
    {
        printf("C_FindObjectsInit failed with error: 0x%lx\n", rv);
        return rv;
    }

    printf("Searching for all objects in the session...\n");

    // Loop to retrieve objects
    do
    {
        rv = P11Functions->C_FindObjects(hSession, objHandles, sizeof(objHandles) / sizeof(CK_OBJECT_HANDLE), &ulObjectCount);
        if (rv != CKR_OK)
        {
            printf("C_FindObjects failed with error: 0x%lx\n", rv);
            P11Functions->C_FindObjectsFinal(hSession);
            return rv;
        }

        // Loop through each found object
        for (CK_ULONG i = 0; i < ulObjectCount; i++)
        {
            // Get the label of the object
            CK_ATTRIBUTE labelAttr = {CKA_LABEL, NULL_PTR, 0};
            rv = P11Functions->C_GetAttributeValue(hSession, objHandles[i], &labelAttr, 1);

            if (rv == CKR_OK && labelAttr.ulValueLen != (CK_ULONG)-1)
            {
                // Allocate memory to store the label
                labelAttr.pValue = malloc(labelAttr.ulValueLen + 1); // +1 for null-terminator
                if (labelAttr.pValue == NULL)
                {
                    printf("Memory allocation failed for label.\n");
                    continue;
                }

                // Retrieve the label
                rv = P11Functions->C_GetAttributeValue(hSession, objHandles[i], &labelAttr, 1);
                if (rv == CKR_OK)
                {
                    // Null-terminate and print the handle and label on one line
                    ((char *)labelAttr.pValue)[labelAttr.ulValueLen] = '\0'; // Null-terminate
                    printf("%lu: Handle = %lu, Label = %s\n", i + 1, objHandles[i], (char *)labelAttr.pValue);
                }
                else
                {
                    printf("%lu: Handle = %lu, Label = <Failed to retrieve label>\n", i + 1, objHandles[i]);
                }

                // Free allocated memory
                free(labelAttr.pValue);
            }
            else
            {
                printf("Object %lu: Handle = %lu, Label = <No Label>\n", i + 1, objHandles[i]);
            }
        }
    } while (ulObjectCount > 0);

    rv = P11Functions->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK)
    {
        printf("C_FindObjectsFinal failed with error: 0x%lx\n", rv);
    }

    return rv;
}

CK_RV EncryptDataWithRSA(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR plainText, CK_ULONG plainText_len, CK_BYTE_PTR *cipherText, CK_ULONG *cipherText_len)
{
    printf(hSession ? "Session Open\n" : "Session Close\n");
    printf("%d\n", hKey);
    printf("%s\n", (char *)plainText);

    CK_MECHANISM mech = {CKM_RSA_PKCS, NULL_PTR, 0}; // RSA 암호화 메커니즘
    CK_RV rv;

    printf("Encrypt Init Process\n");
    rv = P11Functions->C_EncryptInit(hSession, &mech, hKey);
    if (rv != CKR_OK)
    {
        printf("C_EncryptInit failed: 0x%lx\n", rv);
        return rv;
    }

    *cipherText = (CK_BYTE_PTR)malloc(*cipherText_len);
    if (*cipherText == NULL)
    {
        printf("Memory allocation failed for cipherText\n");
        return CKR_HOST_MEMORY;
    }

    printf("Encrypt Init Success\n");

    printf("Encrypt Process...\n");
    rv = P11Functions->C_Encrypt(hSession, plainText, plainText_len, *cipherText, cipherText_len);
    if (rv != CKR_OK)
    {
        printf("C_Encrypt failed: 0x%lx\n", rv);
        free(*cipherText);
        *cipherText = NULL;
        return rv;
    }

    printf("Encrypt Success...\n");

    printf("Encrypted data (hex): ");
    for (CK_ULONG i = 0; i < *cipherText_len; i++)
    {
        printf("%02X ", (*cipherText)[i]);
    }
    printf("\n");

    return CKR_OK;
}

CK_RV DecryptDataWithRSA(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR cipherText, CK_ULONG cipherText_len, CK_BYTE_PTR *plainText, CK_ULONG *plainText_len)
{
    printf(hSession ? "Session Open\n" : "Session Close\n");
    printf("%d\n", hKey);
    printf("%s\n", (char *)cipherText);
    CK_MECHANISM mech = {CKM_RSA_PKCS, NULL_PTR, 0};
    CK_RV rv;

    printf("Decrypt Init Process\n");
    rv = P11Functions->C_DecryptInit(hSession, &mech, hKey);
    if (rv != CKR_OK)
    {
        printf("C_DecryptInit failed: 0x%lx\n", rv);
        return rv;
    }
    printf("Decrypt Init Success\n");

    rv = P11Functions->C_Decrypt(hSession, cipherText, cipherText_len, NULL_PTR, plainText_len);
    if (rv != CKR_OK)
    {
        printf("Failed to get plainText length: 0x%lx\n", rv);
        return rv;
    }

    *plainText = (CK_BYTE_PTR)malloc(*plainText_len);
    if (*plainText == NULL)
    {
        printf("Memory allocation failed for plainText\n");
        return CKR_HOST_MEMORY;
    }

    rv = P11Functions->C_Decrypt(hSession, cipherText, cipherText_len, *plainText, plainText_len);
    if (rv != CKR_OK)
    {
        printf("C_Decrypt failed: 0x%lx\n", rv);
        free(*plainText);
        *plainText = NULL;
        return rv;
    }

    printf("Decrypted text: %.*s\n", (int)*plainText_len, *plainText);
    return CKR_OK;
}

CK_RV SignDataWithECDSA(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR *pSignatureOut, CK_ULONG *pSignatureLengthOut)
{
    printf(hSession ? "Session Open\n" : "Session Close\n");
    printf("Key Handle: %d\n", hKey);

    CK_MECHANISM mech = {CKM_ECDSA_SHA256, NULL_PTR, 0};
    CK_RV rv;
    const char *message = "Hello, world!";
    CK_BYTE_PTR pData = (CK_BYTE_PTR)message;
    CK_ULONG ulDataLen = strlen(message);
    CK_BYTE_PTR pSignature = NULL;
    CK_ULONG signatureLength = 0;

    // Sign initialization
    printf("Sign Init Process\n");
    rv = P11Functions->C_SignInit(hSession, &mech, hKey);
    if (rv != CKR_OK)
    {
        printf("C_SignInit failed: 0x%lx\n", rv);
        return rv;
    }
    printf("Sign Init Success\n");

    // Determine signature length
    rv = P11Functions->C_Sign(hSession, pData, ulDataLen, NULL_PTR, &signatureLength);
    if (rv != CKR_OK || signatureLength == 0)
    {
        printf("Failed to get signature length: 0x%lx\n", rv);
        return rv;
    }

    // Allocate memory for signature and initialize
    pSignature = (CK_BYTE_PTR)malloc(signatureLength);
    if (pSignature == NULL)
    {
        printf("Memory allocation failed for signature\n");
        return CKR_HOST_MEMORY;
    }
    memset(pSignature, 0, signatureLength);

    // Perform signing
    rv = P11Functions->C_Sign(hSession, pData, ulDataLen, pSignature, &signatureLength);
    if (rv != CKR_OK)
    {
        printf("C_Sign failed: 0x%lx\n", rv);
        free(pSignature);
        return rv;
    }

    printf("Signature successful. Signature length: %lu\n", signatureLength);
    printf("Signature (hex): ");
    for (CK_ULONG i = 0; i < signatureLength; i++)
    {
        printf("%02X ", pSignature[i]);
    }
    printf("\n");

    FILE *file = fopen(SIGNATURE_FILE, "wb");
    if (file)
    {
        fwrite(pSignature, 1, signatureLength, file);
        fclose(file);
        printf("Signature saved to %s\n", SIGNATURE_FILE);
    }
    else
    {
        printf("Failed to save signature to file\n");
        free(pSignature);
        return CKR_FUNCTION_FAILED;
    }

    printf("Signature successful. Signature length: %lu\n", signatureLength);

    free(pSignature);
    return CKR_OK;
}
CK_RV VerifyDataWithECDSA(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pSignature, CK_ULONG signatureLength)
{
    printf(hSession ? "Session Open\n" : "Session Close\n");
    printf("Key Handle: %d\n", hKey);

    CK_MECHANISM mech = {CKM_ECDSA_SHA256, NULL_PTR, 0};
    CK_RV rv;
    const char *message = "Hello, world!";
    CK_BYTE_PTR pData = (CK_BYTE_PTR)message;
    CK_ULONG ulDataLen = strlen(message);

    printf("Verify Init Process\n");
    rv = P11Functions->C_VerifyInit(hSession, &mech, hKey);
    if (rv != CKR_OK)
    {
        printf("C_VerifyInit failed: 0x%lx\n", rv);
        free(pSignature);
        return rv;
    }
    printf("Verify Init Success\n");

    rv = P11Functions->C_Verify(hSession, pData, ulDataLen, pSignature, signatureLength);
    if (rv == CKR_OK)
    {
        printf("Verification successful.\n");
    }
    else if (rv == CKR_SIGNATURE_INVALID)
    {
        printf("Verification failed: Invalid signature.\n");
    }
    else
    {
        printf("Verification failed with error: 0x%lx\n", rv);
    }

    free(pSignature);
    return rv;
}

/*
    FUNCTION:        int main(int argc, char* argv[])
*/
int main(int argc, char *argv[])
{
    int rc = -1;
    CK_RV rv = CKR_TOKEN_NOT_PRESENT;
    CK_SESSION_HANDLE hSession = 0;
    CK_SLOT_ID ckSlot = SLOT;
    CK_BYTE bPassword[64] = PASSWORD;

    memset(PlainText, 65, sizeof(PlainText));

    if (argc < 2)
    {
        printf("Need args\n");
        return rc;
    }

    int listKeys = 0;
    int generateKey = 0;
    int encryptFlag = 0;
    int decryptFlag = 0;
    int signFlag = 0;
    int verifyFlag = 0;
    int keyHandle = 0;
    char keyType[16] = "";
    char keyLabel[64] = "";
    char plainText[256] = "";

    CK_BYTE *cipherText = NULL;
    CK_BYTE *decryptedText = NULL;
    CK_ULONG cipherText_len;
    CK_ULONG decryptedText_len;
    CK_BYTE_PTR pSignature = NULL;
    CK_ULONG signatureLength = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-li") == 0 || strcmp(argv[i], "-list") == 0)
        {
            listKeys = 1;
        }
        else if (strcmp(argv[i], "-gen") == 0)
        {
            generateKey = 1;
            if (i + 1 < argc && (strcmp(argv[i + 1], "-key") == 0 || strcmp(argv[i + 1], "-keyType") == 0))
            {
                strncpy(keyType, argv[i + 2], sizeof(keyType) - 1);
                keyType[sizeof(keyType) - 1] = '\0';
                i += 2;
            }
        }
        else if (strcmp(argv[i], "-enc") == 0)
        {
            encryptFlag = 1;
            if (i + 1 < argc && (strcmp(argv[i + 1], "-text") == 0))
            {
                strncpy(plainText, argv[i + 2], sizeof(plainText) - 1);
                plainText[sizeof(plainText) - 1] = '\0';
                i += 2;
            }
        }
        else if (strcmp(argv[i], "-dec") == 0)
        {
            decryptFlag = 1;
        }
        else if (strcmp(argv[i], "-sign") == 0)
        {
            signFlag = 1;
        }
        else if (strcmp(argv[i], "-verify") == 0)
        {
            verifyFlag = 1;
        }
        else if (strcmp(argv[i], "-handle") == 0 && i + 1 < argc)
        {
            keyHandle = atoi(argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "-label") == 0 && i + 1 < argc)
        {
            strncpy(keyLabel, argv[i + 1], sizeof(keyLabel) - 1);
            keyLabel[sizeof(keyLabel) - 1] = '\0';
            i++;
        }
    }

    if (LoadP11Functions() == CK_FALSE)
    {
        printf("Failed to load PKCS11 library!\n");
        return rc;
    }
    if (LoadSfntExtensionFunctions() == CK_FALSE)
    {
        printf("Failed to load SafeNet extension functions!\n");
        return rc;
    }

    rv = P11Functions->C_OpenSession(ckSlot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK)
    {
        printf("Failed to open session! rv = 0x%lx\n", rv);
        return rc;
    }

    rv = P11Functions->C_Login(hSession, CKU_USER, bPassword, (CK_ULONG)strlen((char *)bPassword));
    printf("Success CO Login\n");
    if (rv != CKR_OK)
    {
        printf("Failed to login! rv = 0x%lx\n", rv);
        P11Functions->C_CloseSession(hSession);
        return rc;
    }

    if (listKeys)
    {
        rv = FindAllObjects(hSession);
        if (rv != CKR_OK)
        {
            printf("Failed to list keys! rv = 0x%lx\n", rv);
        }
    }
    else if (generateKey)
    {
        if (strcmp(keyType, "rsa") == 0 && strlen(keyLabel) > 0)
        {
            rv = GenerateRSAKeyPair(hSession, keyLabel);
            if (rv != CKR_OK)
            {
                printf("Failed to generate RSA key pair! rv = 0x%lx\n", rv);
            }
        }
        else if (strcmp(keyType, "ecdsa") == 0 && strlen(keyLabel) > 0)
        {
            rv = GenerateECDSAKeyPair(hSession, keyLabel);
            if (rv != CKR_OK)
            {
                printf("Failed to generate ECDSA key pair! rv = 0x%lx\n", rv);
            }
        }
        else
        {
            printf("Invalid arguments for key generation. Type or label missing.\n");
        }
    }
    else if (encryptFlag)
    {
        rv = EncryptDataWithRSA(hSession, keyHandle, (CK_BYTE_PTR)plainText, strlen((char *)plainText), &cipherText, &cipherText_len);

        if (rv == CKR_OK)
        {
            printf("Encryption succeeded. Ciphertext length: %lu\n", cipherText_len);

            FILE *file = fopen(CIPHERTEXT_FILE, "wb");
            if (file)
            {
                fwrite(cipherText, 1, cipherText_len, file);
                fclose(file);
                printf("Ciphertext saved to %s\n", CIPHERTEXT_FILE);
            }
            else
            {
                printf("Failed to save ciphertext to file\n");
            }
            free(cipherText);
        }
        else
        {
            printf("Encryption failed! rv = 0x%lx\n", rv);
        }
    }
    else if (decryptFlag)
    {
        FILE *file = fopen(CIPHERTEXT_FILE, "rb");
        if (file)
        {
            fseek(file, 0, SEEK_END);
            cipherText_len = ftell(file);
            fseek(file, 0, SEEK_SET);

            cipherText = (CK_BYTE_PTR)malloc(cipherText_len);

            if (cipherText)
            {
                fread(cipherText, 1, cipherText_len, file);
            }
            fclose(file);
            printf("File Load Success\n");
        }
        else
        {
            printf("Failed to load ciphertext from file\n");
            return -1;
        }

        rv = DecryptDataWithRSA(hSession, keyHandle, cipherText, cipherText_len, &decryptedText, &decryptedText_len);
        if (rv == CKR_OK)
        {
            printf("Decryption succeeded. Plaintext: %.*s\n", (int)decryptedText_len, decryptedText);
            free(decryptedText);
        }
        else
        {
            printf("Decryption failed! rv = 0x%lx\n", rv);
        }
        free(cipherText);
    }
    else if (signFlag)
    {

        rv = SignDataWithECDSA(hSession, keyHandle, &pSignature, &signatureLength);

        printf("\n");
        if (rv == CKR_OK)
        {
            printf("Signing succeeded.\n");
        }
        else
        {
            printf("Signing failed! rv = 0x%lx\n", rv);
        }
    }
    else if (verifyFlag)
    {
        FILE *file = fopen(SIGNATURE_FILE, "rb");
        if (file)
        {
            fseek(file, 0, SEEK_END);
            signatureLength = ftell(file);
            fseek(file, 0, SEEK_SET);

            pSignature = (CK_BYTE_PTR)malloc(signatureLength);
            if (pSignature == NULL)
            {
                printf("Memory allocation failed for signature\n");
                fclose(file);
                return CKR_HOST_MEMORY;
            }

            fread(pSignature, 1, signatureLength, file);
            fclose(file);
            printf("Signature loaded from %s\n", SIGNATURE_FILE);
        }
        else
        {
            printf("Failed to load signature from file\n");
            return CKR_FUNCTION_FAILED;
        }
        rv = VerifyDataWithECDSA(hSession, keyHandle, pSignature, signatureLength);
        if (rv == CKR_OK)
        {
            printf("Verification succeeded.\n");
        }
        else
        {
            printf("Verification failed! rv = 0x%lx\n", rv);
        }
    }

    if (rv == CKR_OK)
    {
        printf("All is OKAY!\n");
        rc = 0;
    }
    else
    {
        printf("All is NOT OKAY! rv = 0x%lx\n", rv);
        rc = -1;
    }

    if (P11Functions)
    {
        P11Functions->C_CloseSession(hSession);
        P11Functions->C_Finalize(NULL_PTR);
    }

    if (LibHandle)
    {
#ifdef OS_WIN32
        FreeLibrary(LibHandle);
#else
        dlclose(LibHandle);
#endif
    }

    if (P_DecText)
        free(P_DecText);
    if (P_EncText)
        free(P_EncText);

    return rc;
}