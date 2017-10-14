/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package assignment2;

import java.util.Scanner;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

/**
 *
 * @author Chathu
 */
public class Assignment2 {

    /**
     * @param args the command line arguments
     */
    //first ussing 255bit, create a AES key
     public static String getSecretAESKeyAsString() throws Exception {

        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(255);
        SecretKey secKey = gen.generateKey();
        String encodKey = Base64.getEncoder().encodeToString(secKey.getEncoded());
        return encodKey;

    }
     
     //then use the cteated AES key to encrypet the plain text
    public static String encryptTextUsingAES(String Entered, String aesKeyString) throws Exception {

        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] byteCipherText = aesCipher.doFinal(Entered.getBytes());
        return Base64.getEncoder().encodeToString(byteCipherText);

    }
    
      public static String decryptTextUsingAES(String encryptedText, String aesKeyString) throws Exception {

        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] bytePlainText = aesCipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(bytePlainText);

    }
       private static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

 

        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;

    }
      
    
    public static void main(String[] args) throws Exception {

             Scanner reader = new Scanner(System.in);
                      System.out.print("Please enter the Plain Text : ");
            String  InputText= reader.next();
   
        Map<String, Object> keys = getRSAKeys();
        PublicKey pubKey = (PublicKey) keys.get("Pub");
        PrivateKey pvtKey = (PrivateKey) keys.get("Pvt");

        String secAESKeyString = getSecretAESKeyAsString();
        
        String encrText = encryptTextUsingAES(InputText, secAESKeyString);
        String encryptedAESKeyString = encryptAESKey(secAESKeyString, pvtKey);

        String decryptedAESKeyString = decryptAESKey(encryptedAESKeyString, pubKey);
        String decryptedText = decryptTextUsingAES(encrText, decryptedAESKeyString);

        System.out.println(" Thid is the Plain Text    :      " + InputText); 
        System.out.println("This is the Encrypted Text :      " + encrText);
        System.out.println("This is the decrypted      :      " + decryptedText);
}


    private static String decryptAESKey(String encryptedAESKey, PublicKey publicKey) throws Exception {
    Cipher C = Cipher.getInstance("RSA");
    C.init(Cipher.DECRYPT_MODE, publicKey);
    return new String(C.doFinal(Base64.getDecoder().decode(encryptedAESKey)));

    }

    private static String encryptAESKey(String plainAESKey, PrivateKey privateKey) throws Exception {
     Cipher C = Cipher.getInstance("RSA");
     C.init(Cipher.ENCRYPT_MODE, privateKey);
     return Base64.getEncoder().encodeToString(C.doFinal(plainAESKey.getBytes()));

    }
    
    
}
