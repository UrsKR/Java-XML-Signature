package de.butatopanto.xmlsig;

public class PrivateKeyData {

    public final String pathToKeystore;
    public final char[] passphraseForKeystore;
    public final char[] passphraseForKey;

    public PrivateKeyData(String pathToKeystore, String passphraseForKeystore, String passphraseForKey) {
        this.pathToKeystore = pathToKeystore;
        this.passphraseForKeystore = passphraseForKeystore.toCharArray();
        this.passphraseForKey = passphraseForKey.toCharArray();
    }
}