import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.singletonList;

public class PrivateKeyProvider {

    private XMLSignatureFactory factory;

    public PrivateKeyProvider(XMLSignatureFactory factory) {
        this.factory = factory;
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

   public KeyInfo loadKeyInfo(KeyStore.PrivateKeyEntry keyEntry) {
        X509Certificate certificate = loadCertificate(keyEntry);
        return createKeyInfoFactory(certificate);
    }
}
