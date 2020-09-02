package com.example.doubleratchet.DoubleRatchet;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Connect {

    Socket socket;
    private ServerSocket serverSocket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;

    public void connect(String ip, int port){
        try{
            socket = new Socket(ip, port);
            dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream = new DataOutputStream(socket.getOutputStream());
        } catch (Exception e){
            System.out.println("connect: Error has occured: " + e);
        }
    }

    public void disconnect(){
        try{
            socket.close();
        } catch (Exception e){
            System.out.println("disconnect: Error has occured: " + e);
        }

    }

    public void createServer(int port){
        try{
            serverSocket = new ServerSocket(port);
        } catch (Exception e){
            System.out.println("createServer: Error has occured: " + e);
        }
    }

    public void waitForConnect(){
        try{
            socket = serverSocket.accept();
            dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream = new DataOutputStream(socket.getOutputStream());
        } catch (Exception e){
            System.out.println("waitForConnect: Error has occured: " + e);
        }
    }

    public void disconnectServer(){
        try {
            socket.close();
            serverSocket.close();
        } catch (Exception e){
            System.out.println("disconnectServer: Error has occured: " + e);
        }
    }


    public Socket getSocket() {
        return socket;
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    public DataInputStream getDataInputStream() {
        return dataInputStream;
    }

    public DataOutputStream getDataOutputStream() {
        return dataOutputStream;
    }
}
