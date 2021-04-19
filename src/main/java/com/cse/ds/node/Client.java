package com.cse.ds.node;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;

import com.cse.ds.models.Command;


@SuppressWarnings("Since15")
public abstract class Client implements AutoCloseable {
    /**
     * Socket to receive the requests.
     */
    private DatagramSocket socket;

    public int start() throws SocketException {
        return start(-1);
    }

    public int start(int port) throws SocketException {
        if (socket != null) {
            // Server is already running
            throw new RuntimeException("Server is already running.");
        }
        if (port <= 0) {
            socket = new DatagramSocket();
        } else {
            socket = new DatagramSocket(port);
        }

        int localPort = socket.getLocalPort();
        System.out.println("Server is started at " + localPort);
        startReceiving();

        return localPort;
    }

    /**
     * Close the server.
     */
    public void close() {
        if (socket != null) {
            if (!socket.isClosed()) {
                socket.close();
                socket = null;
                System.out.println("Server is stopped");
            }
        }
    }

    public void send(String messsage, String ip, int port) {
        System.out.println("Sending " + messsage + " to " + ip + ":" + port);
        try {
            DatagramPacket packet = new DatagramPacket(messsage.getBytes(), messsage.getBytes().length,
                    InetAddress.getByName(ip), port);
            socket.send(packet);
        } catch (IOException e) {
            System.out.println(e.getMessage() + e);
        }
    }

    private void startReceiving() {
        new Thread() {
            public void run() {
                while (socket != null && !socket.isClosed()) {
                    byte[] buffer = new byte[Command.BUFFER_SIZE];
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        if (socket != null && !socket.isClosed()) {

                            socket.receive(packet);

                            byte[] data = packet.getData();
                            String message = new String(data, 0, packet.getLength());

                            Node_info response = new Node_info(packet.getAddress().getHostAddress(), packet.getPort(), message);
                            onRequest(response);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
//                        System.out.println("Error in receiving packet." + e);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }
            }
        }.start();
    }

    public abstract void onRequest(Node_info request) throws NoSuchAlgorithmException, IOException, ClassNotFoundException;
}
