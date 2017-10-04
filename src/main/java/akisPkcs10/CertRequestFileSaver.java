package akisPkcs10;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Base64;

public class CertRequestFileSaver {
    private byte[] certRequestData;

    public CertRequestFileSaver(byte[] certRequestData) {
        this.certRequestData = certRequestData;
    }

    public void writeToFileInDerFormat(String fileName) throws IOException {
        writeDataToFile(certRequestData, fileName);
    }

    public void writeToFileInPEMFormat(String fileName) throws IOException {
        String pemFormat = convertToPEM(certRequestData);
        writeDataToFile(pemFormat.getBytes(), fileName);
    }

    private void writeDataToFile(byte[] data, String fileName) throws IOException {
        FileOutputStream out = new FileOutputStream(fileName);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }

    private String convertToPEM(byte[] data) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final PrintStream ps = new PrintStream(out);
        ps.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
        ps.println(Base64.getMimeEncoder().encodeToString(data));
        ps.println("-----END NEW CERTIFICATE REQUEST-----");
        return out.toString();
    }
}
