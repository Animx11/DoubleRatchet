package com.example.doubleratchet.DoubleRatchet;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class TypeConverter {

    public TypeConverter() {
    }

    public void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to typeConverter string
     */
    public String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }

    public PublicKey bytesToPublicKey(byte[] recivedPubKey){
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(recivedPubKey);
            return keyFactory.generatePublic(x509KeySpec);
        } catch (Exception e){
            System.out.println("bytesToPublicKey: Error has occured: " + e);
            return null;
        }
    }

    public byte[] publicKeyToBytes(PublicKey publicKey){
        try{
            return publicKey.getEncoded();
        } catch (Exception e){
            System.out.println("publicKeyToBytes: Error has occured: " + e);
            return null;
        }
    }

}

