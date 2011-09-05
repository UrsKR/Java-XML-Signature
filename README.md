Java XML Signature
==================

This is an example for Java's XML Signature API.
It reads both private key and public key from PKCS12 to sign or validate XML files.

Usage
----------------
Create `PrivateKeyData` by handing a path and the passphrase for the key file and the private key inside.
Create either an `XmlSigner` or an `XmlValidator` with it.
Call `sign` with the path to the unsigned XML file you want to sign and another path indicating where to put the result.
Call `verify` with the path to the signed XML file you want to verify.


License
-----------------
Do what you want. Whether it's modify, copy, distribute, use comercially - I don't care.
The project comes without any warranty whatsoever.