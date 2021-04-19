package com.cse.ds.models;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class FileGenerator {

    private final static int MAXSIZE = 10;
    private final static int MINSIZE = 2;

    private static byte[] generateLargeNumber() {
        int randomNum = ThreadLocalRandom.current().nextInt(MINSIZE + 1, MAXSIZE + 1);
        byte[] number = new byte[randomNum * 1000000];
        Random r = new Random();
        r.nextBytes(number);
        return number;
    }

    public static DummyFile generateDummyFile() {
        byte[] bigint = FileGenerator.generateLargeNumber();
        int size = bigint.length;
        int sizeMB = size / (1024 * 1024);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; i++) {
            sb.append('a');
        }
        String data = sb.toString();

        DummyFile df = new DummyFile();
        df.setSize(sizeMB);
        df.setData(data);
        return df;
    }

    public static byte[] generateFile(String filename) throws IOException, NoSuchAlgorithmException {

        File file = new File(Paths.get("").toAbsolutePath() + "/Hosted_Files/" + filename);
        file.getParentFile().mkdirs();
        file.createNewFile();

        ObjectOutputStream fileOut = new ObjectOutputStream(new FileOutputStream(file));

        DummyFile dummyFile = FileGenerator.generateDummyFile();

        //writing object to file
        fileOut.writeObject(dummyFile);
        fileOut.close();

        byte[] bytes;
        bytes = dummyFile.toByteArray();

        //calculating the hash of the dummy file and writing it
        byte[] fileHash = FileGenerator.generateHash(bytes);
        return fileHash;
    }

    public static byte[] generateHash(byte[] file) throws NoSuchAlgorithmException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(file);
    }

    public static byte[] getHashByteArray(String data) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest.digest(data.getBytes(StandardCharsets.UTF_8));
    }

    public static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }


    public static String getHash(String data) {
        return bytesToHex(getHashByteArray(data));
    }

}
