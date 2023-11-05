package com.nitec.kz.service;

import com.nitec.kz.payload.SignXmlRequest;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PrivilegedExceptionAction;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;

@Service
public class SignWssSec {
    private static final String KEYSTORE_PASSWORD = "Qwerty12";
    private static final String KEYSTORE_KEY = "C:\\Users\\Thanh\\Downloads\\New folder (3)\\shep-service-ws-sample\\shep-ws-security-service\\src\\main\\resources\\keys\\GOSTKNCA_9b4f6827a2736acff3de3948392286d61e13a91c.p12";
    private static final String SIMPLE_XML_SOAP = "<?xml version='1.0' encoding='UTF-8'?>\n" +
            "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
            "\t<S:Body>\n" +
            "\t\t<ns0:sendMessage xmlns:ns0=\"http://bip.bee.kz/AsyncChannel/v10/Types\">\n" +
            "\t\t\t<request>\n" +
            "\t\t\t\t<messageInfo>\n" +
            "\t\t\t\t\t<messageId>5024113e-b70b-479d-8ac7-8c65103e3338</messageId>\n" +
            "\t\t\t\t\t<serviceId>TestService</serviceId>\n" +
            "\t\t\t\t\t<messageType>REQUEST</messageType>\n" +
            "\t\t\t\t\t<messageDate>2018-01-04T19:38:18.518</messageDate>\n" +
            "\t\t\t\t\t<sender>\n" +
            "\t\t\t\t\t\t<senderId>test</senderId>\n" +
            "\t\t\t\t\t\t<password>test</password>\n" +
            "\t\t\t\t\t</sender>\n" +
            "\t\t\t\t</messageInfo>\n" +
            "\t\t\t\t<messageData>\n" +
            "\t\t\t\t\t<data xmlns:ns1=\"http://schemas.simple.kz/test\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ns1:TestObject\">\n" +
            "\t\t\t\t\t\t<status>STARTED</status>\n" +
            "\t\t\t\t\t</data>\n" +
            "\t\t\t\t</messageData>\n" +
            "\t\t\t</request>\n" +
            "\t\t</ns0:sendMessage>\n" +
            "\t</S:Body>\n" +
            "</S:Envelope>";

    private static final String ISO_DATE_PATTERN = "yyyy-MM-dd'T'HH:mm:ssZ";
    private static final SimpleDateFormat SIMPLE_DATE_FORMAT = new SimpleDateFormat(ISO_DATE_PATTERN);

    private static final String MESSAGE_ID_EXP = "{{message_id}}";
    private static final String SIGN_DATE_EXP = "{{sign_date}}";
    private static final String REQUEST_EXP = "{{request}}";
    private static final String SESSION_ID_EXP = "{{session_id}}";

    private static final String SOAP_TEMPLATE = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\n" +
            "    <SOAP-ENV:Header>\n" +
            "        <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" SOAP-ENV:mustUnderstand=\"1\">\n" +
            "            <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "                <ds:SignedInfo>\n" +
            "                    <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
            "                    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311\" />\n" +
            "                    <ds:Reference URI=\"#id-f3375e1f-40ae-4eb4-822b-3ff1f88abf06\">\n" +
            "                        <ds:Transforms>\n" +
            "                            <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
            "                        </ds:Transforms>\n" +
            "                        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#gost34311\" />\n" +
            "                        <ds:DigestValue>2n9rZYByBUZEkBNAol1/9dXmZ+1Hl/AAwJ4PHYp6gdY=</ds:DigestValue>\n" +
            "                    </ds:Reference>\n" +
            "                </ds:SignedInfo>\n" +
            "                <ds:SignatureValue>\n" +
            "                    4jmkAmAGaI4T+tm2zI/rvLfFfbK4EAodK2NlCp4EHz6X9iozolHaV7x67QRizVfiv0wt3MYZVsiC&#13;\n" +
            "                    zyETy6Ax3A==\n" +
            "                </ds:SignatureValue>\n" +
            "                <ds:KeyInfo>\n" +
            "                    <wsse:SecurityTokenReference>\n" +
            "                        <wsse:KeyIdentifier EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\">MIIEbzCCBBmgAwIBAgIUdkie1z94VCfGiazlhIZqVH5X3h8wDQYJKoMOAwoBAQECBQAwUzELMAkGA1UEBhMCS1oxRDBCBgNVBAMMO9Kw0JvQotCi0KvSmiDQmtCj05jQm9CQ0J3QlNCr0KDQo9Co0Ksg0J7QoNCi0JDQm9Cr0pogKEdPU1QpMB4XDTI</wsse:KeyIdentifier>\n" +
            "                    </wsse:SecurityTokenReference>\n" +
            "                </ds:KeyInfo>\n" +
            "            </ds:Signature>\n" +
            "        </wsse:Security>\n" +
            "    </SOAP-ENV:Header>\n" +
            "    <SOAP-ENV:Body wsu:Id=\"id-f3375e1f-40ae-4eb4-822b-3ff1f88abf06\">\n" +
            "        <ns3:SendMessage xmlns:ns2=\"http://bip.bee.kz/SyncChannel/v10/Interfaces\" xmlns:ns3=\"http://bip.bee.kz/SyncChannel/v10/Types\">\n" +
            "            <request>\n" +
            "                <requestInfo>\n" +
            "                    <messageId>{{message_id}}</messageId>\n" +
            "                    <serviceId>Torelik_SearchApi_2</serviceId>\n" +
            "                    <messageDate>{{sign_date}}</messageDate>\n" +
            "                    <sender>\n" +
            "                        <senderId>user</senderId>\n" +
            "                        <password>password</password>\n" +
            "                    </sender>\n" +
            "                    <sessionId>{{{session_id}}}</sessionId>\n" +
            "                </requestInfo>\n" +
            "                <requestData>\n" +
            "                    <data>\n" +
            "                        <key>a3acd9842447e4753665f5795b7f7bdb</key>\n" +
            "                        <request>{{request}}</request>\n" +
            "                    </data>\n" +
            "                </requestData>\n" +
            "            </request>\n" +
            "        </ns3:SendMessage>\n" +
            "    </SOAP-ENV:Body>\n" +
            "</soap:Envelope>";

    public String signXml(SignXmlRequest signXmlRequest) {

        KalkanProvider kalkanProvider = new KalkanProvider();
        Security.addProvider(kalkanProvider);
        KncaXS.loadXMLSecurity();
        String now = SIMPLE_DATE_FORMAT.format(new Date());
        String populatedTemplate = SOAP_TEMPLATE.replace(MESSAGE_ID_EXP, signXmlRequest.getMessageId())
                .replace(SESSION_ID_EXP, signXmlRequest.getSessionId())
                .replace(REQUEST_EXP, signXmlRequest.getRequestContent())
                .replace(SIGN_DATE_EXP, now);

        try {
            final String signMethod;
            final String digestMethod;
            InputStream is = new ByteArrayInputStream(populatedTemplate.getBytes());

            SOAPMessage msg = MessageFactory.newInstance().createMessage(null, is);

            SOAPEnvelope env = msg.getSOAPPart().getEnvelope();
            SOAPBody body = env.getBody();

            String bodyId = "id-" + UUID.randomUUID().toString();
            body.addAttribute(new QName(WSConstants.WSU_NS, "Id", WSConstants.WSU_PREFIX), bodyId);

            SOAPHeader header = env.getHeader();
            if (header == null) {
                header = env.addHeader();
            }
            KeyStore store = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);
            InputStream inputStream;
            inputStream = AccessController.doPrivileged(new PrivilegedExceptionAction<InputStream>() {
                @Override
                public FileInputStream run() throws Exception {
                    return new FileInputStream(KEYSTORE_KEY);
                }
            });
            store.load(inputStream, KEYSTORE_PASSWORD.toCharArray());
            Enumeration<String> als = store.aliases();
            String alias = null;
            while (als.hasMoreElements()) {
                alias = als.nextElement();
            }
            final PrivateKey privateKey = (PrivateKey) store.getKey(alias, KEYSTORE_PASSWORD.toCharArray());
            final X509Certificate x509Certificate = (X509Certificate) store.getCertificate(alias);
            String sigAlgOid = x509Certificate.getSigAlgOID();
            if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "sha1";
            } else if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
                digestMethod = XMLCipherParameters.SHA256;
            } else {
                signMethod = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "gost34311";
            }

            Document doc = env.getOwnerDocument();
            Transforms transforms = new Transforms(env.getOwnerDocument());
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            Element c14nMethod = XMLUtils.createElementInSignatureSpace(doc, "CanonicalizationMethod");
            c14nMethod.setAttributeNS(null, "Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            Element signatureMethod = XMLUtils.createElementInSignatureSpace(doc, "SignatureMethod");
            signatureMethod.setAttributeNS(null, "Algorithm", signMethod);

            XMLSignature sig = new XMLSignature(env.getOwnerDocument(), "", signatureMethod, c14nMethod);

            sig.addDocument("#" + bodyId, transforms, digestMethod);
            sig.getSignedInfo().getSignatureMethodElement().setNodeValue(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            WSSecHeader secHeader = new WSSecHeader();
            secHeader.setMustUnderstand(true);
            secHeader.insertSecurityHeader(env.getOwnerDocument());
            secHeader.getSecurityHeader().appendChild(sig.getElement());
            header.appendChild(secHeader.getSecurityHeader());

            SecurityTokenReference reference = new SecurityTokenReference(doc);
            reference.setKeyIdentifier(x509Certificate);

            sig.getKeyInfo().addUnknownElement(reference.getElement());
            sig.sign(privateKey);

            String signedSoap = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            System.out.println(signedSoap);

            verifyXml(signedSoap, x509Certificate);
            return signedSoap;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


    public boolean verifyXml(String xmlString, X509Certificate x509Certificate) {
        boolean result = false;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document doc = documentBuilder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));

            Element sigElement = null;
            Element rootEl = (Element) doc.getFirstChild();

            NodeList list = rootEl.getElementsByTagName("ds:Signature");
            int length = list.getLength();
            System.out.println(length);
            for (int i = 0; i < length; i++) {
                Node sigNode = list.item(length - 1);
                sigElement = (Element) sigNode;
                if (sigElement == null) {
                    System.err.println("Bad signature: Element 'ds:Reference' is not found in XML document");
                }
                XMLSignature signature = new XMLSignature(sigElement, "");
                if (x509Certificate != null) {
                    result = signature.checkSignatureValue(x509Certificate);
//                    rootEl.removeChild(sigElement);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("VERIFICATION RESULT IS: " + result);
        return result;
    }
}
