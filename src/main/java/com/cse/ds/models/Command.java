package com.cse.ds.models;
import java.util.Arrays;
import java.util.List;


public final class Command {
    private Command() {
    }

    public static final int BOOTSTRAP_SERVER_PORT = 55555;
    public static final String BOOTSTRAP_SERVER_HOST = "127.0.0.1";
    public static final int BUFFER_SIZE = 65536;

    public static final String REG = "REG";
    public static final String REGOK = "REGOK";

    public static final String UNREG = "UNREG";
    public static final String UNROK = "UNROK";

    public static final String ECHO = "ECHO";

    public static final String JOIN = "JOIN";
    public static final String JOINOK = "JOINOK";

    public static final String LEAVE = "LEAVE";
    public static final String LEAVEOK = "LEAVEOK";

    public static final String DISCON = "DISCON";
    public static final String DISOK = "DISOK";

    public static final String SER = "SER";
    public static final String SERACK = "SERACK";
    public static final String SEROK = "SEROK";
    public static final String SERACKOK = "SERACKOK";

    public static final String ERROR = "ERROR";

    public static final List<String> FILE_NAME_LIST = Arrays.asList("Adventures of Tintin","Jack and Jill" ,"Glee" , "The Vampire Diarie" , "King Arthur" , "Windows XP" , "Harry Potter" , "Kung Fu Panda" , "Lady Gaga" , "Twilight" , "Windows 8" , "Mission Impossible" , "Turn Up The Music" , "Super Mario" , "American Pickers" , "Microsoft Office 2010" , "Happy Feet" , "Modern Family" , "American Idol" , "Hacking for Dummies");

}
