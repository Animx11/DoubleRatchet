package com.example.doubleratchet.DoubleRatchet;

import at.favre.lib.crypto.HKDF;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RatchetCipher {

    byte[] encKey, autKey, iv;

    private void getCreditales(byte[] messageKey){

        byte[] salt = new byte[80];
        for (byte b : salt) {
            b = 0x00;
        }

        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(salt, messageKey);
        encKey = HKDF.fromHmacSha256().expand(pseudoRandomKey, "encKey".getBytes(), 32);
        autKey = HKDF.fromHmacSha256().expand(pseudoRandomKey, "autKey".getBytes(), 32);
        iv = HKDF.fromHmacSha256().expand(pseudoRandomKey, "iv".getBytes(), 16);

    }


    public byte[] decryptMessage(byte[] receivedEncryptedMessage, byte[] messageKey){
        try{

            getCreditales(messageKey);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec1 = new SecretKeySpec(encKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKeySpec1, ivParameterSpec);

            return cipher.doFinal(receivedEncryptedMessage);

        } catch (Exception e){
            System.out.println("decryptMessage: Error has occured: " + e);
            return null;
        }
    }


    public byte[] encryptMessage(byte[] messageKey, String message){

        try {

            getCreditales(messageKey);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(encKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(message.getBytes());

        } catch (Exception e){
            System.out.println("encryptMessage: Error has occured: " + e);
            return null;
        }
    }

}
