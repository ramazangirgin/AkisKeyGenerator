package akisPkcs10;

import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;
import tr.gov.tubitak.uekae.esya.api.asn.pkcs10.ECertificationRequestInfo;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.SignatureAlg;
import tr.gov.tubitak.uekae.esya.api.crypto.exceptions.CryptoException;
import tr.gov.tubitak.uekae.esya.api.crypto.util.KeyUtil;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.CardType;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.SmartCard;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.SmartCardException;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.SmartOp;
import tr.gov.tubitak.uekae.esya.api.smartcard.pkcs11.card.keytemplate.asymmetric.rsa.RSAKeyPairTemplate;
import tr.gov.tubitak.uekae.esya.asn.pkcs10.CertificationRequestInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAKeyGenParameterSpec;

public class AkisKeyGenerator {

    private String cardPin;
    private String keyLabel;
    private String subjectName;

    public AkisKeyGenerator(String cardPin, String keyLabel, String subjectName) {
        this.cardPin = cardPin;
        this.keyLabel = keyLabel;
        this.subjectName = subjectName;
    }

    public byte[] generateKeyAndSignPKCS10RequestSHA256RSA() throws PKCS11Exception, SmartCardException, IOException, CryptoException, NoSuchAlgorithmException {
        SmartCard smartCard = new SmartCard(CardType.AKIS);
        long[] slots = smartCard.getSlotList();
        long slotNo = slots[0];
        long sessionId = smartCard.openSession(slotNo);
        smartCard.login(sessionId, cardPin);
        PublicKey publicKey = createRSA2048SignatureKeyInCard(smartCard, sessionId, keyLabel);
        X500Name x500Name = new X500Name(subjectName);
        byte[] certificationRequestInfoBytes = createCertificationRequestInfo(x500Name, publicKey);
        byte[] certRequestInfoSignature = SmartOp.sign(smartCard, sessionId, slotNo, keyLabel, certificationRequestInfoBytes, SignatureAlg.RSA_SHA256.getName());

        String certRequestSignatureAlgName = "SHA256WithRSA";
        return createCertificationRequestValue(certificationRequestInfoBytes, certRequestSignatureAlgName, certRequestInfoSignature);
    }

    private PublicKey createRSA2048SignatureKeyInCard(SmartCard smartCard, long sessionId, String keyLabel) throws PKCS11Exception, SmartCardException, IOException, CryptoException {
        RSAKeyPairTemplate rsaKeyPairTemplate = new RSAKeyPairTemplate(keyLabel, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        rsaKeyPairTemplate.getAsTokenTemplate(true, false);
        KeySpec keySpec = smartCard.createKeyPair(sessionId, rsaKeyPairTemplate);
        KeySpec publicKeySpec = smartCard.readPublicKeySpec(sessionId, keyLabel);
        return KeyUtil.generatePublicKey(publicKeySpec);
    }

    private byte[] createCertificationRequestInfo(X500Name x500Name, PublicKey publicKey) throws IOException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.putInteger(BigInteger.ZERO);
        x500Name.encode(der1);
        der1.write(publicKey.getEncoded());

        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte) 48, der1);
        return der2.toByteArray();
    }

    private byte[] createCertificationRequestValue(byte[] certReqInfo, String signAlgo, byte[] signature) throws IOException, NoSuchAlgorithmException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.write(certReqInfo);

        AlgorithmId.get(signAlgo).encode(der1);
        der1.putBitString(signature);

        // final DER encoded output
        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte) 48, der1);
        return der2.toByteArray();
    }
}
