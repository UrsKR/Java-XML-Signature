import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.singletonList;

public class PrivateKeyProvider {

    private final XMLSignatureFactory factory;
    private final KeyStore.PrivateKeyEntry keyEntry;

    public PrivateKeyProvider(XMLSignatureFactory factory) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableEntryException {
        this.factory = factory;
        KeyStore keyStore = loadKeystore();
        keyEntry = loadSigningKey(keyStore);
    }

    public KeyInfo loadKeyInfo() {
        X509Certificate certificate = loadCertificate(keyEntry);
        return createKeyInfoFactory(certificate);
    }

    public PrivateKey loadPrivateKey() {
        return keyEntry.getPrivateKey();
    }

    private X509Certificate loadCertificate(KeyStore.PrivateKeyEntry keyEntry) {
        return (X509Certificate) keyEntry.getCertificate();
    }

    private KeyInfo createKeyInfoFactory(X509Certificate certificate) {
        KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
        List<Serializable> x509Content = new ArrayList<Serializable>();
        x509Content.add(certificate.getSubjectX500Principal().getName());
        x509Content.add(certificate);
        X509Data data = keyInfoFactory.newX509Data(x509Content);
        return keyInfoFactory.newKeyInfo(singletonList(data));
    }

    private KeyStore loadKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("mykeystore.jks"), "changeit".toCharArray());
        return keyStore;
    }

    private KeyStore.PrivateKeyEntry loadSigningKey(KeyStore keyStore1) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        return (KeyStore.PrivateKeyEntry) keyStore1.getEntry
                ("mykey", new KeyStore.PasswordProtection("changeit".toCharArray()));
    }
}