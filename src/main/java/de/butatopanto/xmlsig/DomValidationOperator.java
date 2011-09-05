package de.butatopanto.xmlsig;

import javax.xml.crypto.dsig.XMLSignatureFactory;

public class DomValidationOperator {

    private static final String Mechanism_Type_Dom = "DOM";
    protected final XMLSignatureFactory factory = XMLSignatureFactory.getInstance(Mechanism_Type_Dom);
}
