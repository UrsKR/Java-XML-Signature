package de.butatopanto.xmlsig;

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

public class Pkcs12PrivateKeyProvider implements PrivateKeyProvider {

    public static final String Keystore_Type_Pkcs12 = "pkcs12";
    private final XMLSignatureFactory factory;
    private final KeyStore.PrivateKeyEntry keyEntry;
    private KeyStore keyStore;
    private PrivateKeyData keyData;

    public Pkcs12PrivateKeyProvider(XMLSignatureFactory factory, PrivateKeyData keyData) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableEntryException {
        this.factory = factory;
        this.keyData = keyData;
        this.keyStore = loadKeystore();
        this.keyEntry = loadKeyEntry();
    }

    public KeyInfo loadKeyInfo() {
        X509Certificate certificate = loadCertificate();
        return createKeyInfoFactory(certificate);
    }

    public PrivateKey loadPrivateKey() {
        return keyEntry.getPrivateKey();
    }

    private X509Certificate loadCertificate() {
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
        KeyStore keyStore = KeyStore.getInstance(Keystore_Type_Pkcs12);
        FileInputStream keystoreStream = new FileInputStream(keyData.pathToKeystore);
        char[] passphrase = keyData.passphraseForKeystore;
        keyStore.load(keystoreStream, passphrase);
        return keyStore;
    }

    private KeyStore.PrivateKeyEntry loadKeyEntry() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        char[] passphrase = keyData.passphraseForKey;
        String alias = keyStore.aliases().nextElement();
        return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(passphrase));
    }
}