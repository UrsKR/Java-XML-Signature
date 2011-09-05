package de.butatopanto.xmlsig;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

public class XmlValidator extends DomValidationOperator {

    private String pathToPublicKeyStore;

    public XmlValidator(String pathToPublicKeyStore) {
        this.pathToPublicKeyStore = pathToPublicKeyStore;
    }

    /**
     * @throws SignatureNotFound if there is not element "Signature" on the top level of the document.
     */
    public boolean isValid(String pathToDocument) throws SignatureNotFound, MarshalException, XMLSignatureException, CertificateException, IOException, SAXException, ParserConfigurationException {
        Document document = loadDocument(pathToDocument);
        PublicKey key = loadPublicKey();
        return validateDocumentWithKey(document, key);
    }

    private boolean validateDocumentWithKey(Document document, PublicKey key) throws MarshalException, XMLSignatureException {
        Node item = findSignatureElement(document);
        DOMValidateContext validateContext = new DOMValidateContext(key, item);
        XMLSignature signature = factory.unmarshalXMLSignature(validateContext);
        return signature.validate(validateContext);
    }

    private Document loadDocument(String pathToDocument) throws SAXException, IOException, ParserConfigurationException {
        return new DocumentReader(pathToDocument).loadDocument();
    }

    private PublicKey loadPublicKey() throws CertificateException, IOException {
        InputStream inStream = new FileInputStream(pathToPublicKeyStore);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();
        return cert.getPublicKey();
    }

    private Node findSignatureElement(Document document) {
        NodeList nodeList = document.getElementsByTagNameNS(XMLNS, "Signature");
        if (nodeList.getLength() == 0) {
            throw new SignatureNotFound();
        }
        return nodeList.item(0);
    }
}