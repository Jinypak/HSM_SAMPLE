/*******************************************************************************
 *
 * Copyright 2015-2019 SafeNet. All rights reserved.
 *
 * This file contains information that is proprietary to SafeNet and may not be
 * distributed or copied without written consent from SafeNet.
 *******************************************************************************/
import java.security.AlgorithmParameters;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaUtils;
import com.safenetinc.luna.provider.LunaProvider;

public class CipherAESKwDemo {

  // Configure these as required.
  private static final int slot = 0; // designated slot
  private static final String passwd = "Apko8085!"; // password
  private static Cipher cipher;
  private static LunaSlotManager manager;

  private static KeyGenerator kg = null;
  private static SecretKey wrappingKey = null;
  private static SecretKey keyToBeWrapped = null;
  private static SecretKey unwrappedAESKey = null;
  private static byte[] wrappedAESKey = null;

  private static byte[] aesEncrypted = null;
  private static byte[] aesDecrypted = null;

  private static byte[] plainText = null;
  private static char[] plainTextBuf = null;

  private static String wrappingMechanism = null;

  // Algorithm parameters
  private static AlgorithmParameters params = null;

  // IV
  private static byte[] iv = null;

  static {
    wrappingMechanism = "AES/KW/NoPadding";
    wrappingMechanism = "AES/KWP/NoPadding";
    iv = new byte[8];
//    for CKM_AES_KWP
    iv = new byte[4];
  }

  // ********************************************
  // Generate the HSM AES keys
  // ********************************************
  private static void generateAESKeys() {
    try {
      manager.setSecretKeysExtractable(true);

      kg = KeyGenerator.getInstance("AES", "LunaProvider");
      kg.init(256);
      wrappingKey = kg.generateKey();
//      keyToBeWrapped = wrappingKey;
      keyToBeWrapped = kg.generateKey();

    } catch (Exception e) {
      System.out.println("Exception generating keys");
      e.printStackTrace();
      System.exit(1);
    }
  }

  // ********************************************
  // Encrypt big plaintext.
  // ********************************************
  private static void encryptPlainText() {
    // Create 63K plaintext approx.
//    plainTextBuf = new char[1024 * 63];//kw succeeds,kwp succeeds
    plainTextBuf = new char[1];//kw fails,kwp succeeds
    plainTextBuf = new char[7];//kw fails,kwp succeeds
    plainTextBuf = new char[8];//kw fails,kwp succeeds
    plainTextBuf = new char[15];//kw fails,kwp succeeds
    plainTextBuf = new char[16];//kw succeeds as min input is 16B
    plainTextBuf = new char[17];//kw fails,kwp succeeds
    plainTextBuf = new char[19];//kw fails,kwp succeeds
    // Fill bytes
    Arrays.fill(plainTextBuf, 'a');
    // Convert to bytes to be encrypted.
    plainText = new String(plainTextBuf).getBytes();

    // Generate random IV
    (new Random()).nextBytes(iv);

    try {

      System.out.println("\n------------------------------------------------------------");
      System.out.println("\nLength of plain text to be encripted: " + plainTextBuf.length + " bytes");
      System.out.println("\nRandom IV: " + LunaUtils.getHexString(iv,false));

      System.out.println("\nCiphering the plain text with HSM AES key");

      params = AlgorithmParameters.getInstance("IV", "LunaProvider");
      params.init(new IvParameterSpec(iv));

      cipher.init(Cipher.ENCRYPT_MODE, keyToBeWrapped, params);

      // For multipart, use update() and final().
//      cipher.update(plainText);
//      aesEncrypted = cipher.doFinal();
      aesEncrypted = cipher.doFinal(plainText);
      System.out.println("confirm : " + plainText);

    } catch (Exception e) {
      System.out.println("Exception ciphering the data with HSM AES key");
      e.printStackTrace();
      System.exit(1);
    }
  }

  // ********************************************
  // Wrap the AES key
  // ********************************************
  private static void wrapAESKey() {
    try {
      System.out.println("\nWrapping of HSM AES key");

      params = cipher.getParameters();
      cipher.init(Cipher.WRAP_MODE, wrappingKey, params);
      wrappedAESKey = cipher.wrap(keyToBeWrapped);

    } catch (Exception ex) {
      System.out.println("Exception during wrapping of HSM AES key");
      ex.printStackTrace();
      System.exit(1);
    }
  }

  // ********************************************
  // Unwrap the AES key
  // ********************************************
  private static void unwrapAESKey() {
    try {
      System.out.println("\nUnwrap wrapped AES key");

      params = cipher.getParameters();
      cipher.init(Cipher.UNWRAP_MODE, wrappingKey, params);
      unwrappedAESKey = (SecretKey) cipher.unwrap(wrappedAESKey, "AES", Cipher.SECRET_KEY);

    } catch (Exception e) {
      System.out.println("Exception attempting to unwrap wrapped AES key");
      e.printStackTrace();
      System.exit(1);
    }
  }

  // ********************************************
  // Decrypt the encrypted value - AES
  // ********************************************
  private static void decryptPlainText() {
    try {

      System.out.println("\nDeciphering the AES-ciphered data");

      params = cipher.getParameters();
//      cipher.init(Cipher.DECRYPT_MODE, keyToBeWrapped, params);
      cipher.init(Cipher.DECRYPT_MODE, unwrappedAESKey, params);

      aesDecrypted = cipher.doFinal(aesEncrypted);

      if (java.util.Arrays.equals(plainText, aesDecrypted)) {
        System.out.println("\nDecryption was successful");
      } else
        System.out.println("\n*** Decryption failed ***");
      System.out.println("\n------------------------------------------------------------\n");

    } catch (Exception e) {
      System.out.println("Exception deciphering the AES-ciphered data");
      e.printStackTrace();
      System.exit(1);
    }
  }

  public static void main(String args[]) {

    System.out.println("AES/KW/NoPadding requires fw version 6.24.2 or higher.");
    System.out.println("AES/KWP/NoPadding requires fw7+");

    manager = LunaSlotManager.getInstance();

    try {
      Security.addProvider(new LunaProvider());
      // log in to the designated slot
      manager.login(slot, passwd);
      cipher = Cipher.getInstance(wrappingMechanism, "LunaProvider");
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("Exception during login");
      System.exit(1);
    }

    // Create the HSM AES keys.
    generateAESKeys();

    // Encrypt big plaintext with random IV - AES
    encryptPlainText();
//    decryptPlainText();

    // Wrap the AES key
    wrapAESKey();

    // unwrap the AES key
    unwrapAESKey();

    // Decrypt the encrypted value - AES
    decryptPlainText();

  }

}
