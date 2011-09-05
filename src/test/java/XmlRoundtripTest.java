import de.butatopanto.xmlsig.PrivateKeyData;
import de.butatopanto.xmlsig.XmlSigner;
import de.butatopanto.xmlsig.XmlValidator;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.net.URL;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class XmlRoundtripTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    private XmlSigner signer;
    private XmlValidator validator;

    @Before
    public void createSignerWithKeyData() throws Exception {
        String pathToKeystore = getPathToFileOnClasspath("certificate.p12");
        String passphraseForKeystore = "pass";
        String passphraseForKey = "pass";
        PrivateKeyData keyData = new PrivateKeyData(pathToKeystore, passphraseForKeystore, passphraseForKey);
        this.signer = new XmlSigner(keyData);
    }

    @Before
    public void createValidatorWithKeyData() throws Exception {
        String pathToPublicKey = getPathToFileOnClasspath("publicKey.p7b");
        this.validator = new XmlValidator(pathToPublicKey);
    }

    @Test
    public void canValidateAFileItSignedItself() throws Exception {
        String pathToInputFile = getPathToInputFile();
        String pathToOutputFile = getPathToOutputFile();
        sign(pathToInputFile, pathToOutputFile);
        validate(pathToOutputFile);
    }

    private void sign(String pathToInputFile, String pathToOutputFile) throws Exception {
        signer.sign(pathToInputFile, pathToOutputFile);
    }

    private void validate(String pathToOutputFile) throws Exception {
        boolean isValid = validator.isValid(pathToOutputFile);
        assertThat(isValid, is(true));
    }

    private String getPathToInputFile() {
        return getPathToFileOnClasspath("unsignedFile.xml");
    }

    private String getPathToFileOnClasspath(String name) {
        URL unsignedXmlUrl = getClass().getClassLoader().getResource(name);
        return unsignedXmlUrl.getFile();
    }

    private String getPathToOutputFile() throws Exception {
        File outputFile = folder.newFile("outputFile");
        return outputFile.getAbsolutePath();
    }
}
