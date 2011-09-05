import de.butatopanto.xmlsig.PrivateKeyData;
import de.butatopanto.xmlsig.XmlSigner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

public class XmlSignerTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    private XmlSigner signer;

    @Before
    public void createSignerWithKeyData() throws Exception {
        String pathToKeystore = getPathToFileOnClasspath("certificate.p12");
        String passphraseForKeystore = "pass";
        String passphraseForKey = "pass";
        PrivateKeyData keyData = new PrivateKeyData(pathToKeystore, passphraseForKeystore, passphraseForKey);
        this.signer = new XmlSigner(keyData);
    }

    @Test
    public void signsFile() throws Exception {
        String pathToInputFile = getPathToInputFile();
        String pathToOutputFile = getPathToOutputFile();
        sign(pathToInputFile, pathToOutputFile);
    }

    private void sign(String pathToInputFile, String pathToOutputFile) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, IOException, UnrecoverableEntryException, CertificateException, ParserConfigurationException, SAXException, MarshalException, XMLSignatureException, TransformerException {
        signer.sign(pathToInputFile, pathToOutputFile);
    }

    private String getPathToInputFile() {
        return getPathToFileOnClasspath("unsignedFile.xml");
    }

    private String getPathToFileOnClasspath(String name) {
        URL unsignedXmlUrl = getClass().getClassLoader().getResource(name);
        return unsignedXmlUrl.getFile();
    }

    private String getPathToOutputFile() throws IOException {
        File outputFile = folder.newFile("outputFile");
        return outputFile.getAbsolutePath();
    }
}
