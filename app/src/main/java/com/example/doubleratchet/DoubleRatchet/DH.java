package com.example.doubleratchet.DoubleRatchet;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class DH {

    public KeyPair generateDH(){
        try{

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            return keyPairGen.generateKeyPair();
        }catch(Exception e){
            System.out.println("generateDH: Error has occurred: " + e);
        }
        return null;
    }

    public byte[] DH(KeyPair keyPair, PublicKey pubKey){
        try{
            KeyAgreement keyAgr = KeyAgreement.getInstance("DH");
            keyAgr.init(keyPair.getPrivate());


            keyAgr.doPhase(pubKey, true);
            return keyAgr.generateSecret();

        } catch (Exception e){
            System.out.println("DH: Error has occurred: " + e);
        }
        return null;
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
