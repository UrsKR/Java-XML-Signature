import org.w3c.dom.Document;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class DocumentWriter {

    private String pathToFile;

    public DocumentWriter() {
        pathToFile = "signedPurchaseOrder.xml";
    }

    public void writeDocument(Document document) throws FileNotFoundException, TransformerException {
        OutputStream stream = new FileOutputStream(pathToFile);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(stream));
    }
}
