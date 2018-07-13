package com.amdocs.banextractor;

import com.sshtools.net.SocketTransport;
import com.sshtools.publickey.SshPrivateKeyFile;
import com.sshtools.publickey.SshPrivateKeyFileFactory;
import com.sshtools.sftp.SftpClient;
import com.sshtools.ssh.*;
import com.sshtools.ssh.components.SshKeyPair;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Slf4j
public class Extractor {
    public enum FileFormat {XML, ZIP, GZIP}

    private static final byte[] GZIP_MAGIC_DIGITS = {0x1F, (byte) 0x8B, 0x08};
    private static final String TAG_TITAN_BAN = "TITAN_BAN";
    private static final String TAG_START = "att:MixedBillService";
    private int depth = 0;
    private StringBuilder stringBuilder = new StringBuilder();
    private boolean doAdd = false;
    private boolean toFile = false;
    private boolean checkTITAN_BAN = false;
    private int depthTITAN_BAN = 0;
    private Writer writer;
    private String BAN;
    private String inputFileName;
    private String outputFileName;
    private FileFormat fileFormat = FileFormat.XML;
    private int SSHport = 22;
    private String serverName;
    private String userName;
    private String password;
    private Path keyFile;
    private boolean needLF = false;
    private int terminalWidth = jline.TerminalFactory.get().getWidth();
    private int lineBAN = 0;

    public Extractor(String BAN, String inputFileName, String outputFileName, String fileFormat) {
        this.BAN = BAN;
        this.inputFileName = inputFileName;
        this.fileFormat = FileFormat.valueOf(fileFormat);

        if ((outputFileName == null) || (outputFileName.trim().equals(""))) {
            this.outputFileName = getFileName4Archive(inputFileName) + getExt();
            log.info("Output file name is empty, constructed new one is {}", this.outputFileName);
        } else if (new File(outputFileName).isDirectory()) {
            this.outputFileName = getFileName4Archive(inputFileName) + getExt();
            log.info("Output file is directory, constructed file name is {}", this.outputFileName);
        } else
            this.outputFileName = outputFileName;
    }

    private String getExt() {
        if (fileFormat.equals(FileFormat.ZIP))
            return ".zip";
        if (fileFormat.equals(FileFormat.GZIP))
            return ".gz";
        return "";
    }

    private String getFileName4Archive(String fileName) {
        final String ext4archive = "." + BAN + ".xml";
        int i = fileName.lastIndexOf('.');
        if (i > -1) {
            String ext = fileName.substring(i + 1);
            if (ext.equals("gz") || ext.equals("xml") || ext.equals("xml"))
                return fileName.substring(0, i) + ext4archive;
        }

        return fileName + ext4archive;
    }

    public static Extractor of(String BAN, String inputFileName, String outputFileName, String fileFormat) {
        return new Extractor(BAN, inputFileName, outputFileName, fileFormat);
    }

    public Extractor setSSH(String serverName, String userName) {
        this.serverName = serverName;
        this.userName = userName;
        return this;
    }

    public Extractor setPassword(String password) {
        this.password = password;
        return this;
    }

    public Extractor setKeyFile(Path keyFile) {
        this.keyFile = keyFile;
        return this;
    }

    public Extractor setSSHport(int SSHport) {
        this.SSHport = SSHport;
        return this;
    }

    private void checkSSHAuthentication(SshClient sshClient, SshAuthentication sshAuthentication) throws SshException {
        int returnCode = sshClient.authenticate(sshAuthentication);

        if (returnCode == SshAuthentication.COMPLETE)
            log.info("Authentication completed");
        else {
            String returnString = "unknown error";
            switch (returnCode) {
                case SshAuthentication.FAILED: returnString = "The authentication failed"; break;
                case SshAuthentication.CANCELLED: returnString = "The authentication was cancelled by the user"; break;
                case SshAuthentication.FURTHER_AUTHENTICATION_REQUIRED: returnString = "The authentication succeeded but further authentication is required"; break;
                case SshAuthentication.PUBLIC_KEY_ACCEPTABLE: returnString = "The public key provided is acceptable for authentication"; break;
            }
            throw new SshException(new Exception("SSH connection haven't established, " + returnString + "[" + returnCode + "]"));
        }
    }

    private static boolean isCompressed(BufferedInputStream inputStream) throws IOException {
        byte[] buf = new byte[GZIP_MAGIC_DIGITS.length];
        inputStream.mark(GZIP_MAGIC_DIGITS.length);
        if (inputStream.read(buf) == GZIP_MAGIC_DIGITS.length) {
            inputStream.reset();
            return (buf[0] == GZIP_MAGIC_DIGITS[0]) && (buf[1] == GZIP_MAGIC_DIGITS[1]) && (buf[2] == GZIP_MAGIC_DIGITS[2]);
        }
        else
            throw new IOException("file too small");
    }

    public void runSSH() throws Exception {
        SshClient sshClient = null;
        log.info("Parsing XML file on SSH server. Server name={}, port={}, login={}", serverName, SSHport, userName);
        try (SocketTransport sshTransport = new SocketTransport(serverName, SSHport);
             AutoCloseable sshClientCloser = (sshClient = SshConnector.createInstance().connect(sshTransport, userName))::exit) {
            if (keyFile != null) {
                log.info("Try to connect using public key file authenthification, key file name={}", keyFile);
                SshPrivateKeyFile pkf = SshPrivateKeyFileFactory.parse(Files.readAllBytes(keyFile));
                SshKeyPair pair = pkf.toKeyPair(password);
                PublicKeyAuthentication pk = new PublicKeyAuthentication();
                pk.setPrivateKey(pair.getPrivateKey());
                pk.setPublicKey(pair.getPublicKey());

                checkSSHAuthentication(sshClient, pk);
            } else {
                log.info("Try to connect using password authentication, password={}", password.substring(0, 1) + "..." + password.substring(password.length() - 1));
                PasswordAuthentication pwd = new PasswordAuthentication();
                pwd.setPassword(password);
                checkSSHAuthentication(sshClient, pwd);
            }

            SftpClient sftp = new SftpClient(sshClient);
            try (AutoCloseable sftpClientCloser = sftp::exit;
                 InputStream inputStream = sftp.getInputStream(inputFileName)) {
                run(inputStream);
            }
        }
    }

    private OutputStream getOutputStream(OutputStream outputStream) throws IOException {
        switch (fileFormat) {
            case ZIP:
                ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream);
                zipOutputStream.setLevel(9);
                zipOutputStream.putNextEntry(new ZipEntry(getFileName4Archive(Paths.get(inputFileName).getFileName().toString())));
                return zipOutputStream;
            case GZIP:
                return new GZIPOutputStream(outputStream);
            default: return null;
        }
    }

    private void run(InputStream inputStream) throws IOException {
        log.info("BAN={}, input file name={}, output file name={}", BAN, inputFileName, outputFileName);
        try(BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
            InputStream inputStreamInternal = isCompressed(bufferedInputStream)  ? new GZIPInputStream(bufferedInputStream) : null;
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outputFileName));
            OutputStream outputStream = getOutputStream(bufferedOutputStream);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter((outputStream == null) ? bufferedOutputStream : outputStream)) {
            extract((inputStreamInternal == null) ? bufferedInputStream : inputStreamInternal, outputStreamWriter);
        } catch (FileNotFoundException fnfe) {
            log.error("File not found: " + inputFileName);
        } catch (IOException ioe) {
            log.error("You have some problem with file: " + inputFileName + ", exception: " + ioe.getLocalizedMessage());
        }  catch (XMLStreamException e) {
            log.error("XMLStreamException", e);
        } finally {
            if (!toFile) {
                log.error("BAN {} has not found", BAN);
                Files.delete(Paths.get(outputFileName));
            }
        }
    }

    public void runLocal() throws IOException {
        log.info("Parsing XML file on local or remote filesystem");
        run(new FileInputStream(inputFileName));
    }

    private void addString(String s) throws IOException {
        if (doAdd)
            if (toFile)
                writer.append(s);
            else
                stringBuilder.append(s);
    }

    private String nameAsString(QName qName) {
        return (StringUtils.isEmpty(qName.getPrefix()) ? "" : (qName.getPrefix() + ":")) + qName.getLocalPart();
    }


    private void addString(StartElement startElement) throws IOException {
        addString("<");
        addString(nameAsString(startElement.getName()));
        // add any attributes
        if (startElement.getAttributes().hasNext()) {
            Iterator it = startElement.getAttributes();
            Attribute attr = null;
            while (it.hasNext()) {
                attr = (Attribute) it.next();
                addString(" " + nameAsString(attr.getName()) + "=\"" + StringEscapeUtils.escapeXml10(attr.getValue()) + "\"");
            }
        }
        // add any namespaces
        if (startElement.getNamespaces().hasNext()) {
            Iterator it = startElement.getNamespaces();
            Namespace attr = null;
            while (it.hasNext()) {
                attr = (Namespace) it.next();
                addString(" ");
                addString(attr.toString());
            }
        }
        addString(">");
    }

    private void lf() {
        System.out.print(needLF ? "\n" : "");
        needLF = false;
    }

    private void printT(String s) {
        System.out.print(s);
        lineBAN += s.length();
    }

    private void resetT() {
        System.out.println("");
        lineBAN = 0;
    }

    private void printBAN(String BAN) {
        if ((lineBAN + BAN.length()) > terminalWidth)
            resetT();

        printT(BAN);

        if (lineBAN == terminalWidth) {
            lineBAN = 0;
            needLF = false;
        } else {
            printT(" ");
            if (lineBAN == terminalWidth) {
                lineBAN = 0;
                needLF = false;
            } else
                needLF = true;
        }
    }

    private void extract(InputStream inputStream, Writer writer) throws XMLStreamException {
        this.writer = writer;
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.FALSE);
        XMLEventReader eventReader = xmlInputFactory.createXMLEventReader(inputStream);

        try (AutoCloseable closer = eventReader::close) {
            while (eventReader.hasNext())
            {
                XMLEvent event = eventReader.nextEvent();

                switch (event.getEventType()) {
                    case XMLStreamConstants.START_ELEMENT:
                        depth++;
                        StartElement startElement = event.asStartElement();
                        String lName = startElement.getName().getLocalPart();

                        switch (lName) {
                            case TAG_START:
                                //if ((depth == 2) || (depth == 1)) {
                                doAdd = true;
                                depthTITAN_BAN = 0;
                                stringBuilder.setLength(0);
                                //}
                                break;
                            case TAG_TITAN_BAN:
                                checkTITAN_BAN = true;
                                depthTITAN_BAN++;
                                break;
                            default:
                                checkTITAN_BAN = false;
                        }
                        addString(startElement);
                        break;
                    case XMLStreamConstants.CHARACTERS:
                        String characters = event.asCharacters().getData();
                        //if (checkTITAN_BAN && ((depth == 4) || (depth == 3))) {
                        if (checkTITAN_BAN) {
                            if (characters.equals(BAN)) {
                                lf();
                                log.info("BAN {} found", BAN);
                                toFile = true;
                                addString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                                addString(stringBuilder.toString());
                                stringBuilder.setLength(0);
                            } else {
                                printBAN(characters);
                                //doAdd = false;
                            }
                        }
                        addString(StringEscapeUtils.escapeXml10(characters));
                        break;
                    case XMLStreamConstants.END_ELEMENT:
                        depth--;
                        //EndElement endElement = event.asEndElement();
                        String endElementName = event.asEndElement().getName().getLocalPart();

                        if (endElementName.equals(TAG_TITAN_BAN)) {
                            checkTITAN_BAN = false;
                            depthTITAN_BAN--;

                            if ((depthTITAN_BAN == 0) && !toFile)
                                doAdd = false;
                        }
                        addString(event.asEndElement().toString());
                        if (toFile && event.asEndElement().getName().getLocalPart().equals(TAG_START))
                            return;
                        break;
                }
            }
            lf();
        } catch (XMLStreamException e) {
            lf();
            log.error("XML parsing error", e);

        } catch (Exception e) {
            lf();
            log.error("Something wrong happend when XMLEventReader was closing", e);
        }
    }
}
