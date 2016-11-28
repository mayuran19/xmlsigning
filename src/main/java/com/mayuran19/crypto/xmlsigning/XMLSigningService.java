package com.mayuran19.crypto.xmlsigning;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

/**
 * Created by mayuran on 28/11/16.
 */
public class XMLSigningService {
    public void signDocument() throws Exception {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);

        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(XMLSigningService.class.getClassLoader().getResourceAsStream("sample.xml"));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expression = "/PurchaseOrder/Item";
        Node widgetNode = (Node) xpath.evaluate(expression, document, XPathConstants.NODE);

        DOMSignContext domSignContext = new DOMSignContext(kp.getPrivate(), document.getDocumentElement(), widgetNode);

        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance();
        Reference ref = xmlSignatureFactory.newReference
                ("", xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null),
                        Collections.singletonList
                                (xmlSignatureFactory.newTransform(Transform.ENVELOPED,
                                        (TransformParameterSpec) null)), null, null);
        SignedInfo si = xmlSignatureFactory.newSignedInfo
                (xmlSignatureFactory.newCanonicalizationMethod
                                (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                                        (C14NMethodParameterSpec) null),
                        xmlSignatureFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                        Collections.singletonList(ref));
        KeyInfoFactory kif = xmlSignatureFactory.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        XMLSignature signature = xmlSignatureFactory.newXMLSignature(si, ki);
        signature.sign(domSignContext);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(document), new StreamResult(System.out));
    }
}
