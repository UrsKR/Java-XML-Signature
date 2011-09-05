import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

import static java.util.Collections.singletonList;
import static javax.xml.crypto.dsig.CanonicalizationMethod.INCLUSIVE;
import static javax.xml.crypto.dsig.SignatureMethod.RSA_SHA1;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;

public class XmlSigner {

    public static final String Entire_Document = "";
    private final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
    private final PrivateKeyProvider provider = new PrivateKeyProvider(factory);

    public void sign() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, IOException, UnrecoverableEntryException, CertificateException, ParserConfigurationException, SAXException, MarshalException, XMLSignatureException, TransformerException {
        SignedInfo signedInfo = createSignature();
        KeyStore keyStore = loadKeystore();
        KeyStore.PrivateKeyEntry keyEntry = loadSigningKey(keyStore);
        KeyInfo keyInfo = provider.loadKeyInfo(keyEntry);
        PrivateKey privateKey = keyEntry.getPrivateKey();
        Document doc = loadDocument();
        sign(doc, privateKey, signedInfo, keyInfo);
        writeDocument(doc);
    }

    private void sign(Document doc, PrivateKey privateKey, SignedInfo signedInfo, KeyInfo keyInfo) throws MarshalException, XMLSignatureException {
        DOMSignContext signContext = new DOMSignContext(privateKey, doc.getDocumentElement());
        XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(signContext);
    }

    private KeyStore.PrivateKeyEntry loadSigningKey(KeyStore ks) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        return (KeyStore.PrivateKeyEntry) ks.getEntry
                ("mykey", new KeyStore.PasswordProtection("changeit".toCharArray()));
    }

    private KeyStore loadKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("mykeystore.jks"), "changeit".toCharArray());
        return keyStore;
    }

    private SignedInfo createSignature() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA1, null);
        Transform transform = factory.newTransform(ENVELOPED, (TransformParameterSpec) null);
        Reference reference = factory.newReference(Entire_Document, digestMethod, singletonList(transform), null, null);
        SignatureMethod signatureMethod = factory.newSignatureMethod(RSA_SHA1, null);
        CanonicalizationMethod canonicalizationMethod = factory.newCanonicalizationMethod(INCLUSIVE, (C14NMethodParameterSpec) null);
        return factory.newSignedInfo(canonicalizationMethod, signatureMethod, singletonList(reference));
    }

    private Document loadDocument() throws SAXException, IOException, ParserConfigurationException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        return documentBuilderFactory.newDocumentBuilder().parse(new FileInputStream("purchaseOrder.xml"));
    }

    private void writeDocument(Document document) throws FileNotFoundException, TransformerException {
        OutputStream stream = new FileOutputStream("signedPurchaseOrder.xml");
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(stream));
    }
}
