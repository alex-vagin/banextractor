package com.amdocs.banextractor;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.cli.*;

import java.nio.file.Paths;
//import org.apache.commons.cli..DefaultParser;

@Slf4j
public class BANExtractorCmd {
    private static final String BAN              = "b";
    private static final String INPUT_FILE_NAME  = "i";
    private static final String OUTPUT_FILE_NAME = "o";
    private static final String FILE_FORMAT      = "f";
    private static final String SSH_SERVER_NAME  = "s";
    private static final String SSH_SERVER_PORT  = "p";
    private static final String SSH_USER_NAME    = "u";
    private static final String SSH_PASSWORD     = "P";
    private static final String SSH_KEY_FILE     = "k";
    private static final String HELP             = "h";
    private static final Options options = new Options();
    private static final CommandLineParser parser = new GnuParser();
    private static CommandLine cmd;

    static {
        options.addOption(HELP, false, "Print this message");
        options.addOption(OptionBuilder.withArgName("BAN").hasArg().withDescription("BAN").create(BAN));
        options.addOption(OptionBuilder.withArgName("fileName").hasArg().withDescription("Input file name").create(INPUT_FILE_NAME));
        options.addOption(OptionBuilder.withArgName("fileName").hasArg().withDescription("Output file name").create(OUTPUT_FILE_NAME));
        options.addOption(OptionBuilder.withArgName("[XML|ZIP|GZIP]").hasArg().withDescription("Output file format [XML|ZIP|GZIP]").create(FILE_FORMAT));
        options.addOption(OptionBuilder.withArgName("serverName").hasArg().withDescription("SSH server name").create(SSH_SERVER_NAME));
        options.addOption(OptionBuilder.withArgName("port").hasArg().withDescription("SSH server port").create(SSH_SERVER_PORT));
        options.addOption(OptionBuilder.withArgName("userName").hasArg().withDescription("User name for SSH server").create(SSH_USER_NAME));
        options.addOption(OptionBuilder.withArgName("password").hasArg().withDescription("Password for password authentication or for private file").create(SSH_PASSWORD));
        options.addOption(OptionBuilder.withArgName("fileName").hasArg().withDescription("Key file for public key authentication to login to SSH server").create(SSH_KEY_FILE));
    }

    private static String getParameter(String parameter) {
        return getParameter(parameter, "");
    }

    private static String getParameter(String parameter, String defultValue) {
        return cmd.hasOption(parameter) ? cmd.getOptionValue(parameter) : defultValue;
    }

    private static void printUsage() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "java -jar banextractor-1.0.jar -b <BAN> -i <fileName> <OPTIONS>", options);
        System.out.println("\nExamples:");
        System.out.println("  get XML from local or remote filesystem :");
        System.out.println("    java -jar banextractor-1.0.jar -b <BAN> -i <fileName>");
        System.out.println("  get XML from SSH server with public authentication (vagrant):");
        System.out.println("    java -jar banextractor-1.0.jar -b <BAN> -i /data/britebill/input-test/extracts/MOBILITY/0202/<SOME_NAME>.gz -s localhost -p 2222 -u ec2-user -k att/att-build/src/main/resources/vagrant/files/ec2-user_id_rsa");
        System.out.println("  get XML from SSH server with password authentication (att):");
        System.out.println("    java -jar banextractor-1.0.jar -b <BAN> -i <fileName> -s <SSH_SERVER> -u <SOME_USER> -P <PASSWORD>");
        System.out.println("\nNotes:");
        System.out.println("  Input file can be either XML or gzipped XML, extractor will uncompress gzipped file \"on-the-fly\"");
        System.out.println("  Output file can be empty, then file will create in the input directory");
        System.out.println("  If output file is directory, then file name will be constructed");
        System.out.println("  File format specifies format of output file, if ZIP or GZIP specified, compression will be done on-the-fly");
        System.out.println("  Temporary files are not created");
        System.out.println("  No size limits for XML");
    }

    public static void main(String[] args) throws Exception {
        try {
            cmd = parser.parse( options, args);

            if (cmd.hasOption(HELP)) {
                printUsage();
                return;
            }

            if (!cmd.hasOption(BAN) || !cmd.hasOption(INPUT_FILE_NAME)) {
                log.error("BAN and input file name are mandatory");
                printUsage();
                return;
            }

            String fileFormat = getParameter(FILE_FORMAT, "XML").toUpperCase();
            if (!fileFormat.equals("XML") && !fileFormat.equals("ZIP") && !fileFormat.equals("GZIP")) {
                log.error("Output file format must be one o the following: XML ZIP GZIP");
                return;
            }

            Extractor extractor = Extractor.of(getParameter(BAN), getParameter(INPUT_FILE_NAME), getParameter(OUTPUT_FILE_NAME), fileFormat).
                    setSSH(getParameter(SSH_SERVER_NAME), getParameter(SSH_USER_NAME)).
                    setSSHport(Integer.parseInt(getParameter(SSH_SERVER_PORT, "22"))).
                    setPassword(getParameter(SSH_PASSWORD)).setKeyFile(Paths.get(getParameter(SSH_KEY_FILE)));

            if (cmd.hasOption(SSH_SERVER_NAME))
                extractor.runSSH();
            else
                extractor.runLocal();
        } catch (ParseException e) {
            log.error("Invalid commandline parameters", e);
        }
    }
}
