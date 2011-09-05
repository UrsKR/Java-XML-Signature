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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

public class XmlValidator extends DomValidationOperator {

    private Pkcs12KeyProvider keyProvider;

    public XmlValidator(PrivateKeyData keyData) throws IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateException {
        keyProvider = new Pkcs12KeyProvider(factory, keyData);
    }

    /**
     * @throws SignatureNotFound if there is not element "Signature" on the top level of the document.
     */
    public boolean isValid(String pathToDocument) throws SignatureNotFound, MarshalException, XMLSignatureException, CertificateException, IOException, SAXException, ParserConfigurationException {
        Document document = loadDocument(pathToDocument);
        return validateDocumentWithKey(document, keyProvider.loadPublicKey());
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

      private Node findSignatureElement(Document document) {
        NodeList nodeList = document.getElementsByTagNameNS(XMLNS, "Signature");
        if (nodeList.getLength() == 0) {
            throw new SignatureNotFound();
        }
        return nodeList.item(0);
    }
}