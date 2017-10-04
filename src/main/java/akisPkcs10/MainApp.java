package akisPkcs10;

import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.common.util.LicenseUtil;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class MainApp {
    public static void main(String[] args) throws Exception {

        loadESYAAPILicense();

        String cardPin = "123456";
        String keyLabel = "rsa-sign-key" + System.currentTimeMillis();
        String pkcs10DerFileName = "CertificateRequest.der";
        String pkcs10PEMFileName = "CertificateRequest.pem";

        String subjectName = "CN=Test,OU=Test,O=Test,L=Test,S=Test,C=Test";
        byte[] pkcs10RequestBytes = new AkisKeyGenerator(cardPin, keyLabel, subjectName).generateKeyAndSignPKCS10RequestSHA256RSA();
        CertRequestFileSaver certRequestFileSaver = new CertRequestFileSaver(pkcs10RequestBytes);
        certRequestFileSaver.writeToFileInDerFormat(pkcs10DerFileName);
        certRequestFileSaver.writeToFileInPEMFormat(pkcs10PEMFileName);
    }

    private static boolean loadESYAAPILicense() throws ESYAException, FileNotFoundException {
        return LicenseUtil.setLicenseXml(new FileInputStream("lisans/lisans.xml"));
    }
}
