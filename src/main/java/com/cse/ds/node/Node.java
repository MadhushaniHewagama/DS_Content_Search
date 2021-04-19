package com.cse.ds.node;

import java.io.*;
import java.net.*;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import com.cse.ds.models.Command;
import com.cse.ds.models.DummyFile;
import com.cse.ds.models.FileGenerator;

import static jdk.nashorn.internal.runtime.regexp.joni.Config.log;

public class Node extends Client {

    // this node details
    private String ip = "127.0.0.1";
    private int port;
    private ArrayList<Node_info> neighbours;
    private String message;
    Set<String> node_files;
    HashMap<String, File> file_set;

    public Node() {
        this.neighbours = new ArrayList<Node_info>();

        Random r = new Random();
        node_files = new LinkedHashSet<String>();
        while (node_files.size() < 5) {
            Integer next = r.nextInt(20);
            node_files.add(Command.FILE_NAME_LIST.get(next));
            file_set = new HashMap<String, File>();
            try {
                file_set.put(Command.FILE_NAME_LIST.get(next), File.createTempFile(Command.FILE_NAME_LIST.get(next), ".txt"));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void run() {
        try {
            port = start();

            String regString = "0114 REG " + ip + " " + port + " user" + port;

            send(regString, Command.BOOTSTRAP_SERVER_HOST, Command.BOOTSTRAP_SERVER_PORT);
        } catch (SocketException e) {
            System.out.println("Failed to start the node: " + e.getMessage());
        }
    }

    public void join(Node_info info) {

        neighbours.add(info);
        String newJoin1 = "0111 JOIN " + ip + " " + port;
        send(newJoin1, info.getIp(), info.getPort());

    }

    public void handleLeave(Node_info node) {

        for (Node_info item : neighbours) {
            if (item.getPort() == node.getPort()) {
                neighbours.remove(item);
                break;
            }
        }
    }

    // diconnecting node
    public void disconnect() {

        if (neighbours.size() == 2) {
            Node_info node1 = neighbours.remove(0);
            if(neighbours.size() == 2){
                Node_info node2 = neighbours.remove(1);
                send("0114 JOIN" + node1.getIp() + " " + node1.getPort(), node2.getIp(), node2.getPort());
                send("0114 JOIN" + node2.getIp() + " " + node2.getPort(), node1.getIp(), node1.getPort());
            }else{
                send("0114 LEAVE " + ip + " " + port, node1.getIp(), node1.getPort());
            }
        } else if (neighbours.size() == 1) {
            Node_info node1 = neighbours.remove(0);
            send("0114 LEAVE " + ip + " " + port, node1.getIp(), node1.getPort());
        }

        String unRegString = "0114 UNREG " + ip + " " + port + " user" + port;
        send(unRegString, Command.BOOTSTRAP_SERVER_HOST, Command.BOOTSTRAP_SERVER_PORT);

    }

    // search
    public void search(String fileName) {
        String searchString = "0047 SER 127.0.0.1 " + port + " " + fileName + " 0";
        for (Node_info item : neighbours) {
            send(searchString, item.getIp(), item.getPort());
        }
    }

    // main method
    public static void main(String args[]) {

        // create node object
        Node node = new Node();
        Scanner sc = new Scanner(System.in);
        // run the node
        node.run();

        System.out.println("Node is started and runing on: " + node.port);
        System.out.println("Avilable file list : " + Arrays.toString(node.node_files.toArray()));
        
        loop:
        while (true) {
            System.out.println("\nSelect option : \n1: Search\n2: Disconnect");
            int option = Integer.parseInt(sc.nextLine().trim());
            switch (option) {
                case 1: // search
                    System.out.println("Enter the fileName: ");
                    node.search(sc.nextLine().trim());
                    break;
                case 2:// disconnect
                    System.out.println("Disconnecting..");
                    node.disconnect();
                    node.close();
                    System.exit(0);
                    break loop;
                default:
                    System.out.println("Invalid input!! Please Try Again");
                    break;
            }
        }
    }

    public void onRequest(Node_info request) throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
        String message = request.getMessage();
        String senderIP = request.getIp();
        int senderPort = request.getPort();

        StringTokenizer tokenizer = new StringTokenizer(message, " ");
        String length = tokenizer.nextToken();
        String command = tokenizer.nextToken();
        if (Command.REGOK.equals(command)) {
            int no_nodes = Integer.parseInt(tokenizer.nextToken());

            switch (no_nodes) {
                case 0:
                    // This is the first node registered to the BootstrapServer.
                    // Do nothing
                    break;

                case 1:
                    String ipAddress = tokenizer.nextToken();
                    int portNumber = Integer.parseInt(tokenizer.nextToken());
                    join(new Node_info(ipAddress, portNumber));
                    break;

                case 2:
                    Node_info nodeA = new Node_info(tokenizer.nextToken(), Integer.parseInt(tokenizer.nextToken()));
                    Node_info nodeB = new Node_info(tokenizer.nextToken(), Integer.parseInt(tokenizer.nextToken()));

                    // JOIN to only one node
                    join(nodeA);
                    join(nodeB);

                    // join(nodeA, nodeB);
                    break;
                case 3:
                    Node_info node1 = new Node_info(tokenizer.nextToken(), Integer.parseInt(tokenizer.nextToken()));
                    Node_info node2 = new Node_info(tokenizer.nextToken(), Integer.parseInt(tokenizer.nextToken()));
                    Node_info node3 = new Node_info(tokenizer.nextToken(), Integer.parseInt(tokenizer.nextToken()));

                    // JOIN to only one node
                    join(node1);
                    join(node2);
                    join(node3);

                    // join(nodeA, nodeB);
                    break;

                case 9996:
                    System.out.println("Failed to register. BootstrapServer is full.");
                    close();
                    break;

                case 9997:
                    System.out.println("Failed to register. This ip and port is already used by another Node.");
                    close();
                    break;

                case 9998:
                    System.out.println("You are already registered. Please unregister first.");
                    close();
                    break;

                case 9999:
                    System.out.println("Error in the command. Please fix the error");
                    close();
                    break;
            }

        } else if (Command.UNROK.equals(command)) {
            System.out.println("Successfully unregistered this node");
        } else if (Command.JOIN.equals(command)) {
            Node_info sender = new Node_info(senderIP, senderPort);
            String ipAddress = tokenizer.nextToken();
            int portNumber = Integer.parseInt(tokenizer.nextToken());
            neighbours.add(new Node_info(ipAddress, portNumber));
            String reply = "0014 JOINOK 0";
            send(reply, senderIP, senderPort);
        } else if (Command.JOINOK.equals(command)) {
            String value = tokenizer.nextToken();
            if (value.equals("0")) {


            }
        } else if (Command.LEAVE.equals(command)) {
            String ipAddress = tokenizer.nextToken();
            int portNumber = Integer.parseInt(tokenizer.nextToken());
            handleLeave(new Node_info(ipAddress, portNumber));
            String reply = "0015 LEAVEOK 0";
            send(reply, senderIP, senderPort);
        } else if (Command.LEAVEOK.equals(command)) {
            String value = tokenizer.nextToken();
            if (value.equals("0")) {
            }
        } else if (Command.DISCON.equals(command)) {
            disconnect();
            String reply = "0114 DISOK 0";
            send(reply, senderIP, senderPort);

            close();
            System.exit(0);

        } else if (Command.SER.equals(command)) {
            String sourceIp = tokenizer.nextToken();
            int sourcePort = Integer.parseInt(tokenizer.nextToken());
            int hops = 0;

            StringBuilder queryBuilder = new StringBuilder();
            int noOfTokens = tokenizer.countTokens();
            for (int i = 1; i < noOfTokens; i++) {
                queryBuilder.append(tokenizer.nextToken());
                queryBuilder.append(' ');
            }
            String lastToken = tokenizer.nextToken();
            int numberOfHops = 0;
            try {
                // no of hops is added at last
                hops = Integer.parseInt(lastToken);
                numberOfHops = hops;
            } catch (NumberFormatException e) {
                queryBuilder.append(lastToken);
            }
            String fileName = queryBuilder.toString().trim();
            boolean fileFound = false;
            System.out.println("Request from " + senderIP + ":" + senderPort + " searching for " + fileName + " " + System.currentTimeMillis());
            hops++;
            ArrayList<String> results = new ArrayList<String>();

            if (fileName != null && !fileName.trim().equals("")) {
                fileName = fileName.toLowerCase();

                for (String node_file : node_files) {
                    boolean file_contains = node_file.toLowerCase().contains(fileName);
                    if (file_contains) {
                        results.add(node_file.replaceAll(" ", "_"));
                        fileFound = true;
                        System.out.println("------------------File Found!---------------------");
                        break;
                    }
                }
            }
            if (fileFound) {
                String resultString = "0114 SEROK " + results.size() + " 127.0.0.1 " + port + " " + hops;
                for (int i = 0; i < results.size(); i++) {
                    resultString += " " + results.get(i);
                }
                send(resultString, sourceIp, sourcePort);
                serveFile(port, results.get(0));
            }
            // Pass the message to neighbours
            if (numberOfHops > 0) {
                for (Node_info item : neighbours) {
                    if (senderIP.equals(item.getIp()) && senderPort != item.getPort() && !fileFound) {
                        //not forward to sender node
                        numberOfHops--;
                        String[] msg_strings = message.split(" ");
                        msg_strings[msg_strings.length - 1] = Integer.toString(numberOfHops);
                        message = Arrays.toString(msg_strings);
                        send(message, item.getIp(), item.getPort());
                    }
                }
            }


        } else if (Command.SEROK.equals(command)) {
            int fileCount = Integer.parseInt(tokenizer.nextToken());

            // Remove port and ip od origin
            tokenizer.nextToken();
            tokenizer.nextToken();

            int hops = Integer.parseInt(tokenizer.nextToken());

            if (fileCount == 0) {
                System.out.println("No files found at " + senderIP + ":" + senderPort + " " + System.currentTimeMillis());
            }
            if (fileCount == 1) {
                String filename = tokenizer.nextToken();
                System.out.println("1 file found at " + senderIP + ":" + senderPort + " " + System.currentTimeMillis());
                System.out.println("\t" + filename);

                System.out.print("Requesting to download ... ");
                downloadFile(senderIP, senderPort, filename);
            }
            if (fileCount > 1) {
                System.out.println(fileCount + " files found at " + senderIP + ":" + senderPort);
                for (int i = 0; i < fileCount; i++) {
                    System.out.println("\t" + tokenizer.nextToken());
                }
            }
        } else if (Command.ERROR.equals(command)) {
            System.out.println("Something went wrong.");
        } else {
            String reply = "0010 ERROR";
            send(reply, senderIP, senderPort);
        }
    }

    private void downloadFile(String senderIP, int senderPort, String filename) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        boolean validated = false;
        while (!validated) {
            System.out.println("Validated");
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println(senderIP + " " + senderPort);
            Socket clientSock = new Socket(senderIP, senderPort);
            System.out.println("Try to receive .. ");
            String hash = Node.receive(clientSock);
            clientSock.close();
            validated = Node.validateDownload(new File(filename), hash);
        }
        System.out.println("File \"" + filename + "\" Downloaded successfully!\n");
    }

    public static void serveFile(int serverPort, String filename) throws IOException, NoSuchAlgorithmException {

        File file = new File(Paths.get("").toAbsolutePath() + "/Hosted_Files/" + filename);

        byte[] hashBytes = FileGenerator.generateFile(filename);
        String hash = FileGenerator.bytesToHex(hashBytes);

        ServerSocket serverSocket = new ServerSocket(serverPort);
        Socket sock = serverSocket.accept();

        send(file, hash, sock);
    }

    public static void send(File file, String hash, Socket socket) {

        try {
            String filename = file.getName();
            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            //sending filename
            dos.writeUTF(filename);
            dos.flush();

            //sending hash
            dos.writeUTF(hash);

            int n = 0;
            byte[] buf = new byte[4092];

            FileInputStream fis = new FileInputStream(file);
            System.out.println("Sending file: " + filename);
            while ((n = fis.read(buf)) != -1) {
                dos.write(buf, 0, n);
                dos.flush();
            }
            dos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static String receive(Socket socket) {
        String hash = null;
        System.out.println("Receving ..");
        try {
            DataInputStream dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            String filename = dis.readUTF();

            hash = dis.readUTF();
            System.out.println("SHA-256-checksum of the file " + filename + "\n" + hash);

            int n = 0;
            byte[] buf = new byte[8192];

            System.out.println("Receiving file: " + filename);
            File file = new File(Paths.get("").toAbsolutePath() + "/Downloads/" + filename);
            file.getParentFile().mkdirs();
            file.createNewFile();

            FileOutputStream fos = new FileOutputStream(file);

            while ((n = dis.read(buf)) != -1) {
                fos.write(buf, 0, n);
                fos.flush();
            }
            fos.close();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            return hash;
        }
    }

    public static boolean validateDownload(File file, String hash) throws IOException, NoSuchAlgorithmException, ClassNotFoundException {

        byte[] fileBytes;
        DummyFile dummyFile = (DummyFile) new ObjectInputStream(
                new FileInputStream(Paths.get("").toAbsolutePath() + "/Downloads/" + file)).readObject();
        fileBytes = dummyFile.toByteArray();

        //calculating the hash of the dummy file
        byte[] calculatedHashBytes = FileGenerator.generateHash(fileBytes);
        String calculatedHash = FileGenerator.bytesToHex(calculatedHashBytes);

        return hash.equalsIgnoreCase(calculatedHash);
    }
}
