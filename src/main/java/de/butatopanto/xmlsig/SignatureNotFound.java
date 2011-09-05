package de.butatopanto.xmlsig;

public class SignatureNotFound extends RuntimeException {

    public SignatureNotFound() {
        super("Cannot find Signature element.");
    }
}
