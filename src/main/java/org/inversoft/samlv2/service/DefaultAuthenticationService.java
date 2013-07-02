/*
 * Copyright (c) 2013, Inversoft Inc., All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
package org.inversoft.samlv2.service;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.UUID;
import java.util.zip.Deflater;

import org.inversoft.samlv2.domain.AuthenticationRequest;
import org.inversoft.samlv2.domain.AuthenticationResponse;
import org.inversoft.samlv2.domain.ConfirmationMethod;
import org.inversoft.samlv2.domain.NameIDFormat;
import org.inversoft.samlv2.domain.ResponseStatus;
import org.inversoft.samlv2.domain.User;
import org.inversoft.samlv2.domain.UserConfirmation;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.AssertionType;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.EncryptedElementType;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.NameIDType;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.SubjectConfirmationDataType;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.SubjectConfirmationType;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.SubjectType;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.NameIDPolicyType;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.ResponseType;
import org.joda.time.DateTime;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @author Brian Pontarelli
 */
public class DefaultAuthenticationService implements AuthenticationService {
  @Override
  public AuthenticationRequest buildRequest(String issuer, NameIDFormat format, boolean sign, KeyPair keyPair) {
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
    if (sign) {
      sign(document.getDocumentElement(), keyPair);
    }

    byte[] rawResult = documentToBytes(document);
    String encodedResult = deflateAndEncode(rawResult);
    return new AuthenticationRequest(id, encodedResult, rawResult);
  }

  @Override
  public AuthenticationResponse parseResponse(String encodedResponse, boolean verifySignature, Key key) {
    byte[] decodedResponse;
    try {
      decodedResponse = new BASE64Decoder().decodeBuffer(encodedResponse);
    } catch (IOException e) {
      throw new RuntimeException("Unable to decode the SAML authentication response", e);
    }

    Document document = parseFromBytes(decodedResponse);
    if (verifySignature) {
      verifySignature(document, key);
    }

    AuthenticationResponse response = new AuthenticationResponse();
    ResponseType jaxbResponse = unmarshallFromDocument(document, ResponseType.class);
    response.status = ResponseStatus.fromSAMLFormat(jaxbResponse.getStatus().getStatusCode().getValue());
    response.id = jaxbResponse.getID();
    response.issuer = parseIssuer(jaxbResponse.getIssuer());
    response.instant = toJodaDateTime(jaxbResponse.getIssueInstant());
    response.destination = jaxbResponse.getDestination();

    List<Object> assertions = jaxbResponse.getAssertionOrEncryptedAssertion();
    for (Object assertion : assertions) {
      if (assertion instanceof EncryptedElementType) {
        throw new RuntimeException("This library currently doesn't handle encrypted assertions");
      }

      AssertionType assertionType = (AssertionType) assertion;
      SubjectType subject = assertionType.getSubject();
      if (subject != null) {
        List<JAXBElement<?>> elements = subject.getContent();
        for (JAXBElement<?> element : elements) {
          Class<?> type = element.getDeclaredType();
          if (type == NameIDType.class) {
            if (response.user != null) {
              throw new RuntimeException("This library currently does not handle multiple NameID elements in the Response assertions.");
            }

            // Extract the name
            response.user = parseUser((NameIDType) element.getValue());
          } else if (type == SubjectConfirmationType.class) {
            // Extract the confirmation
            response.confirmation = parseConfirmation((SubjectConfirmationType) element.getValue());
          } else if (type == EncryptedElementType.class) {
            throw new RuntimeException("This library currently doesn't handle encrypted assertions");
          }
        }
      }
    }

    return response;
  }

  private String deflateAndEncode(byte[] result) {
    byte[] deflatedResult = new byte[result.length];
    Deflater deflater = new Deflater();
    deflater.setInput(result);
    deflater.finish();
    int length = deflater.deflate(deflatedResult);
    String base64 = new BASE64Encoder().encode(ByteBuffer.wrap(deflatedResult, 0, length));
    return base64.replaceAll("\n", "").replaceAll("\r", "");
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

  private UserConfirmation parseConfirmation(SubjectConfirmationType subjectConfirmationType) {
    UserConfirmation userConfirmation = new UserConfirmation();
    SubjectConfirmationDataType data = subjectConfirmationType.getSubjectConfirmationData();
    if (data != null) {
      userConfirmation.address = data.getAddress();
      userConfirmation.inResponseTo = data.getInResponseTo();
      userConfirmation.notBefore = toJodaDateTime(data.getNotBefore());
      userConfirmation.notOnOrAfter = toJodaDateTime(data.getNotOnOrAfter());
      userConfirmation.recipient = data.getRecipient();
    }

    userConfirmation.method = ConfirmationMethod.fromSAMLFormat(subjectConfirmationType.getMethod());

    return userConfirmation;
  }

  private Document parseFromBytes(byte[] bytes) {
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);
    try {
      DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
      return builder.parse(new ByteArrayInputStream(bytes));
    } catch (ParserConfigurationException e) {
      throw new RuntimeException("Unable to parse SAML v2.0 authentication response", e);
    } catch (SAXException e) {
      throw new RuntimeException("Unable to parse SAML v2.0 authentication response", e);
    } catch (IOException e) {
      throw new RuntimeException("Unable to parse SAML v2.0 authentication response", e);
    }
  }

  private String parseIssuer(NameIDType issuer) {
    if (issuer == null) {
      return null;
    }

    return issuer.getValue();
  }

  private User parseUser(NameIDType nameID) {
    NameIDFormat format = NameIDFormat.fromSAMLFormat(nameID.getFormat());
    String qualifier = nameID.getNameQualifier();
    String spQualifier = nameID.getSPNameQualifier();
    String spProviderID = nameID.getSPProvidedID();
    String id = nameID.getValue();
    return new User(format, id, qualifier, spProviderID, spQualifier);
  }

  private void sign(Node node, KeyPair keyPair) {
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

      KeyInfoFactory kif = fac.getKeyInfoFactory();
      KeyValue kv = kif.newKeyValue(keyPair.getPublic());

      KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

      DOMSignContext dsc = new DOMSignContext(keyPair.getPrivate(), node);

      XMLSignature signature = fac.newXMLSignature(si, ki);
      signature.sign(dsc);
    } catch (Exception e) {
      throw new RuntimeException("Unable to sign XML document.", e);
    }
  }

  private DateTime toJodaDateTime(XMLGregorianCalendar instant) {
    if (instant == null) {
      return null;
    }

    return new DateTime(instant.toGregorianCalendar());
  }

  @SuppressWarnings("unchecked")
  private <T> T unmarshallFromDocument(Document document, Class<T> type) {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Unmarshaller unmarshaller = context.createUnmarshaller();
      return (T) unmarshaller.unmarshal(document.getDocumentElement());
    } catch (JAXBException e) {
      throw new RuntimeException("Unable to unmarshall SAML response", e);
    }
  }

  private void verifySignature(Document document, Key key) {
    NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0) {
      return;
    }

    DOMValidateContext validateContext = new DOMValidateContext(key, nl.item(0));
    XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
    try {
      XMLSignature signature = factory.unmarshalXMLSignature(validateContext);
      boolean valid = signature.validate(validateContext);
      if (!valid) {
        throw new RuntimeException("Invalid SAML v2.0 authentication response. The signature is invalid.");
      }
    } catch (MarshalException e) {
      throw new RuntimeException("Unable to verify XML signature in the SAML v2.0 authentication response because we couldn't unmarshall the XML Signature element", e);
    } catch (XMLSignatureException e) {
      throw new RuntimeException("Unable to verify XML signature in the SAML v2.0 authentication response. The signature was unmarshalled we couldn't validate it for an unknown reason", e);
    }
  }
}
