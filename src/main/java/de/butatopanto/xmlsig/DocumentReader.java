package de.butatopanto.xmlsig;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.FileInputStream;
import java.io.IOException;

public class DocumentReader {

    private String pathToFile;

    public DocumentReader(String pathToFile) {
        this.pathToFile = pathToFile;
    }

    public Document loadDocument() throws SAXException, IOException, ParserConfigurationException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        return documentBuilderFactory.newDocumentBuilder().parse(new FileInputStream(pathToFile));
    }
}