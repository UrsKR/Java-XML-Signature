package de.butatopanto.xmlsig;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

public class XmlValidator extends DomValidationOperator {

    public boolean isValid(Document document) throws Exception {
        // Find Signature element.
        NodeList nl =
                document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
// Create a DOMValidateContext and specify a KeySelector
// and document context.
        DOMValidateContext valContext = new DOMValidateContext
                (new X509KeySelector(), nl.item(0));
        XMLSignature signature = factory.unmarshalXMLSignature(valContext);
        return signature.validate(valContext);
    }
}
