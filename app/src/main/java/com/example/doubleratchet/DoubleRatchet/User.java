package com.example.doubleratchet.DoubleRatchet;

import at.favre.lib.crypto.HKDF;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;

import static java.lang.Integer.parseInt;

public class User {

    int MAX_SKIP = 10;


    DH dh;
    TypeConverter typeConverter;
    RatchetCipher ratchetCipher;
    Connect connect;


    // Ratchet variables

    KeyPair dhSend;
    PublicKey dhReceive;
    byte[] rootKey;
    byte[] chainKeySend, chainKeyReceive;
    int ns, nr, pn;
    HashMap<byte[], byte[]> mkSkipped;




    public User() {
        dh = new DH();
        typeConverter = new TypeConverter();
        ratchetCipher = new RatchetCipher();
        connect = new Connect();

    }


    // masterKeyExchange

    public void initializeMasterKeyExchange(boolean alice) {

        try{

            if(alice){
                connect.connect("localhost", 6666);
            } else {
                connect.createServer(6666);
                connect.waitForConnect();
            }

            KeyPair keyPair = dh.generateDH();
            connect.getDataOutputStream().writeUTF(String.valueOf(keyPair.getPublic().getEncoded().length));
            connect.getDataOutputStream().write(keyPair.getPublic().getEncoded());
            int lengthPubKey = parseInt(connect.getDataInputStream().readUTF());
            byte[] pubKey = new byte[lengthPubKey];
            connect.getDataInputStream().readFully(pubKey);

            byte[] sharedSecret = dh.DH(keyPair, typeConverter.bytesToPublicKey(pubKey));

            if(alice){
                initializeDoubleRatchetAlice(pubKey, sharedSecret);
            } else {
                initializeDoubleRatchetBob(keyPair, sharedSecret);
            }


        } catch (Exception e){
            System.out.println("initializeMasterKeyExchange: Error has occured: " + e);
        }

    }

    // DoubleRatchet

    private void initializeDoubleRatchetAlice(byte[] bobPubKey, byte[] masterKey){

        try{

            dhSend = dh.generateDH();
            dhReceive = typeConverter.bytesToPublicKey(bobPubKey);



            byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(masterKey, dh.DH(dhSend, dhReceive));

            rootKey = HKDF.fromHmacSha256().expand(pseudoRandomKey, "RootKey".getBytes(), 32);
            chainKeySend = HKDF.fromHmacSha256().expand(pseudoRandomKey, "ChainKey".getBytes(), 32);


            chainKeyReceive = null;
            ns = nr = pn = 0;
            mkSkipped = new HashMap<byte[], byte[]>();


        } catch (Exception e){
            System.out.println("initializeDoubleRatchet: Error has occured: " + e);
        }

    }

    private void initializeDoubleRatchetBob(KeyPair bobKeyPair, byte[] masterKey){

        try{

            dhSend = bobKeyPair;
            dhReceive = null;
            rootKey = masterKey;
            chainKeySend = null;
            chainKeyReceive = null;
            ns = nr = pn = 0;
            mkSkipped = new HashMap<byte[], byte[]>();

        } catch (Exception e){
            System.out.println("initializeDoubleRatchet: Error has occured: " + e);
        }

    }

    // Sending and receiving message

    public void sendMessage(String message){
        try{

            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(chainKeySend, "HmacSHA256");
            mac.init(secretKeySpec);



            byte[] messageKey = mac.doFinal("messageKey".getBytes());
            chainKeySend = mac.doFinal("chainKey".getBytes());
            ns += 1;

            byte[] encryptedMessage = ratchetCipher.encryptMessage(messageKey, message);

            //  HEADER sending data
            connect.getDataOutputStream().writeUTF(String.valueOf(dhSend.getPublic().getEncoded().length));
            connect.getDataOutputStream().write(dhSend.getPublic().getEncoded());
            connect.getDataOutputStream().writeUTF(String.valueOf(pn));
            connect.getDataOutputStream().writeUTF(String.valueOf(ns));
            connect.getDataOutputStream().writeUTF(String.valueOf(encryptedMessage.length));
            connect.getDataOutputStream().write(encryptedMessage);




        } catch (Exception e) {
            System.out.println("sendMessage: Error has occured: " + e);
        }
    }

    public byte[] receivingMessage(){

        try{

            // Reading data

            int receivedPubKeyLength = parseInt(connect.getDataInputStream().readUTF());
            byte[] receivedPubKey = new byte[receivedPubKeyLength];
            connect.getDataInputStream().readFully(receivedPubKey);

            int receivedPN = parseInt(connect.getDataInputStream().readUTF());
            int receivedNS = parseInt(connect.getDataInputStream().readUTF());
            int receivedEncryptedMessageLength = parseInt(connect.getDataInputStream().readUTF());
            byte[] receivedEncryptedMessage = new byte[receivedEncryptedMessageLength];
            connect.getDataInputStream().readFully(receivedEncryptedMessage);

            // End reading data

            byte[] plaintext = trySkippedMessageKeys(receivedPubKey, receivedEncryptedMessage);
            if(plaintext != null){
                return plaintext;
            }
            if(dhReceive == null){
                skipMessageKeys(receivedPN);
                dhRatchet(receivedPubKey);
            }
            else if(Arrays.equals(receivedPubKey, dhReceive.getEncoded()) != true){
                skipMessageKeys(receivedPN);
                dhRatchet(receivedPubKey);
            }

            //Na razie to padło
            //skipMessageKeys(receivedNS);

            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(chainKeyReceive, "HmacSHA256");
            mac.init(secretKeySpec);


            byte[] messageKey = mac.doFinal("messageKey".getBytes());
            chainKeyReceive = mac.doFinal("chainKey".getBytes());
            nr += 1;

            return ratchetCipher.decryptMessage(receivedEncryptedMessage, messageKey);



        } catch (Exception e){
            System.out.println("receivingMessage: Error has occured: " + e);
            return null;
        }

    }

    private byte[] trySkippedMessageKeys(byte[] receivedPubKey, byte[] receivedEncryptedMessage){
        try{

            if(mkSkipped.isEmpty()){
                return null;
            }
            else if(mkSkipped.containsKey(receivedPubKey)){
                byte[] messageKey = mkSkipped.get(receivedPubKey);
                mkSkipped.remove(receivedPubKey);
                return ratchetCipher.decryptMessage(receivedEncryptedMessage, messageKey);
            } else {
                return null;
            }

        }catch (Exception e){
            System.out.println("trySkippedMessageKeys: Error has occured: " + e);
            return null;
        }
    }

    private void skipMessageKeys(int until){
        try{

            if(nr + MAX_SKIP < until){
                throw new Exception("Too many skipped messages");
            }
            if(dhReceive != null){
                while(nr < until){

                    Mac mac = Mac.getInstance("HmacSHA256");
                    SecretKeySpec secretKeySpec = new SecretKeySpec(chainKeyReceive, "HmacSHA256");
                    mac.init(secretKeySpec);

                    byte[] messageKey = mac.doFinal("messageKey".getBytes());
                    chainKeyReceive = mac.doFinal("chainKey".getBytes());
                    mkSkipped.put(dhReceive.getEncoded(), messageKey);
                    nr += 1;
                }
            }

        }catch (Exception e){
            System.out.println("skipMessageKeys: Error has occured: " + e);
        }
    }

    private void dhRatchet(byte[] receivedPubKey){
        pn = ns;
        ns = nr = 0;
        dhReceive = typeConverter.bytesToPublicKey(receivedPubKey);

        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(rootKey, dh.DH(dhSend, dhReceive));

        setRootKey(HKDF.fromHmacSha256().expand(pseudoRandomKey, "RootKey".getBytes(), 32));
        setChainKeyReceive(HKDF.fromHmacSha256().expand(pseudoRandomKey, "ChainKey".getBytes(), 32));

        dhSend = dh.generateDH();

        pseudoRandomKey = HKDF.fromHmacSha256().extract(rootKey, dh.DH(dhSend, dhReceive));

        setRootKey(HKDF.fromHmacSha256().expand(pseudoRandomKey, "RootKey".getBytes(), 32));
        setChainKeySend(HKDF.fromHmacSha256().expand(pseudoRandomKey, "ChainKey".getBytes(), 32));


    }



    // Getters and setters


    public KeyPair getDhSend() {
        return dhSend;
    }

    public void setDhSend(KeyPair dhSend) {
        this.dhSend = dhSend;
    }

    public PublicKey getDhReceive() {
        return dhReceive;
    }

    public void setDhReceive(PublicKey dhReceive) {
        this.dhReceive = dhReceive;
    }

    public byte[] getRootKey() {
        return rootKey;
    }

    public void setRootKey(byte[] rootKey) {
        this.rootKey = rootKey;
    }

    public byte[] getChainKeySend() {
        return chainKeySend;
    }

    public void setChainKeySend(byte[] chainKeySend) {
        this.chainKeySend = chainKeySend;
    }

    public byte[] getChainKeyReceive() {
        return chainKeyReceive;
    }

    public void setChainKeyReceive(byte[] chainKeyReceive) {
        this.chainKeyReceive = chainKeyReceive;
    }

    public int getNs() {
        return ns;
    }

    public void setNs(int ns) {
        this.ns = ns;
    }

    public int getNr() {
        return nr;
    }

    public void setNr(int nr) {
        this.nr = nr;
    }

    public int getPn() {
        return pn;
    }

    public void setPn(int pn) {
        this.pn = pn;
    }

    public HashMap<byte[], byte[]> getMkSkipped() {
        return mkSkipped;
    }

    public void setMkSkipped(HashMap<byte[], byte[]> mkSkipped) {
        this.mkSkipped = mkSkipped;
    }


}
