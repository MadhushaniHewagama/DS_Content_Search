package com.cse.ds.node;

public class Node_info {
    private String ip;
    private int port;
    private String username;
    private String message;

    public Node_info(String ip, int port) {
        this.ip = ip;
        this.port = port;
    }

    public Node_info(String ip, int port, String username,String message){
        this.ip = ip;
        this.port = port;
        this.username = username;
        this.message = message;
    }

    public Node_info(String ip, int port, String message) {
        this.ip = ip;
        this.port = port;

        this.message = message;
}

    public String getIp(){
        return this.ip;
    }

    public String getUsername(){
        return this.username;
    }
    public int getPort(){
        return this.port;
    }

    public String getMessage(){return this.message;}
}
