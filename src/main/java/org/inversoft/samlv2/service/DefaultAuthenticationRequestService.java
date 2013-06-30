package org.inversoft.samlv2.service;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.UUID;
import java.util.zip.Deflater;

import org.inversoft.samlv2.domain.AuthenticationRequest;
import org.inversoft.samlv2.domain.AuthenticationResponse;
import org.inversoft.samlv2.domain.NameIDFormat;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.NameIDType;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.NameIDPolicyType;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.ResponseType;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @author Brian Pontarelli
 */
public class DefaultAuthenticationRequestService implements AuthenticationRequestService {
  @Override
  public AuthenticationRequest buildRequest(String issuer, NameIDFormat format) {
    String id = UUID.randomUUID().toString();

    AuthnRequestType jaxbRequest = new AuthnRequestType();
    jaxbRequest.setIssuer(new NameIDType());
    jaxbRequest.getIssuer().setValue(issuer);
    jaxbRequest.setNameIDPolicy(new NameIDPolicyType());
    jaxbRequest.getNameIDPolicy().setAllowCreate(true);
    jaxbRequest.getNameIDPolicy().setFormat(format.toSAMLFormat());
    jaxbRequest.setID(id);
    jaxbRequest.setIssueInstant(new XMLGregorianCalendarImpl(new GregorianCalendar()));
    jaxbRequest.setVersion("2.0");

    Document document = marshallToDocument(jaxbRequest, AuthnRequestType.class);
    sign(document.getDocumentElement());

    byte[] rawResult = documentToBytes(document);
    String encodedResult = deflateAndEncode(rawResult);

    return new AuthenticationRequest(id, encodedResult, rawResult);
  }

  @Override
  public AuthenticationResponse parseResponse(String response) {
    byte[] decodedResponse = new BASE64Decoder().decodeBuffer(response);
    ResponseType jaxbResponse = unmarshallFromBytes(decodedResponse, ResponseType.class);
    String status = jaxbResponse.getStatus().getStatusCode().getValue();
    return new AuthenticationResponse();
  }

  @SuppressWarnings("unchecked")
  private <T> T unmarshallFromBytes(byte[] bytes, Class<T> type) {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Unmarshaller unmarshaller = context.createUnmarshaller();
      return (T) unmarshaller.unmarshal(new ByteArrayInputStream(bytes));
    } catch (JAXBException e) {
      throw new RuntimeException("Unable to unmarshall SAML response", e);
    }
  }

  private String deflateAndEncode(byte[] result) {
    byte[] deflatedResult = new byte[result.length];
    Deflater deflater =  new Deflater();
    deflater.setInput(result);
    deflater.finish();
    int length = deflater.deflate(deflatedResult);
    return new BASE64Encoder().encode(ByteBuffer.wrap(deflatedResult, 0, length));
  }

  private byte[] documentToBytes(Document document) {
    try {
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer t = tf.newTransformer();
      DOMSource source = new DOMSource(document);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      StreamResult result = new StreamResult(baos);
      t.transform(source, result);
      return baos.toByteArray();
    } catch (TransformerException e) {
      throw new RuntimeException("Unable to write DOM object to a byte[]", e);
    }
  }

  private <T> Document marshallToDocument(T object, Class<T> type) {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Marshaller marshaller = context.createMarshaller();
      DOMResult domResult = new DOMResult();
      marshaller.marshal(object, domResult);
      return (Document) domResult.getNode();
    } catch (JAXBException e) {
      // Rethrow as runtime
      throw new RuntimeException("Unable to marshall JAXB SAML object to DOM for signing.", e);
    }
  }

  private void sign(Node node) {
    try {
      XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

      Reference ref = fac.newReference("",
          fac.newDigestMethod(DigestMethod.SHA1, null),
          Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (XMLStructure) null)),
          null, null);

      SignedInfo si = fac.newSignedInfo(
          fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (XMLStructure) null),
          fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null),
          Collections.singletonList(ref));

      KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
      kpg.initialize(512);
      KeyPair kp = kpg.generateKeyPair();

      KeyInfoFactory kif = fac.getKeyInfoFactory();
      KeyValue kv = kif.newKeyValue(kp.getPublic());

      KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

      DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), node);

      XMLSignature signature = fac.newXMLSignature(si, ki);
      signature.sign(dsc);
    } catch (Exception e) {
      throw new RuntimeException("Unable to sign XML document.", e);
    }
  }
}
