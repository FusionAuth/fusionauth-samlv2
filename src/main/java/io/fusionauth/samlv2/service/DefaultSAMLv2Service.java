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
package io.fusionauth.samlv2.service;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.Deflater;

import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.ConfirmationMethod;
import io.fusionauth.samlv2.domain.NameIDFormat;
import io.fusionauth.samlv2.domain.ResponseStatus;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.User;
import io.fusionauth.samlv2.domain.UserConfirmation;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AssertionType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AttributeStatementType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AttributeType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AudienceRestrictionType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.ConditionAbstractType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.ConditionsType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.EncryptedElementType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.NameIDType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.OneTimeUseType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.ProxyRestrictionType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.StatementAbstractType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.SubjectConfirmationDataType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.SubjectConfirmationType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.SubjectType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.NameIDPolicyType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.ObjectFactory;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.ResponseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * @author Brian Pontarelli
 */
public class DefaultSAMLv2Service implements SAMLv2Service {
  private static final Logger logger = LoggerFactory.getLogger(DefaultSAMLv2Service.class);

  @Override
  public String buildHTTPRedirectAuthnRequest(String id, String issuer, String relayState, boolean sign, PrivateKey key,
                                              Algorithm algorithm)
      throws SAMLException {
    // SAML Web SSO profile requirements (section 4.1.4.1)
    AuthnRequestType authnRequest = new AuthnRequestType();
    authnRequest.setIssuer(new NameIDType());
    authnRequest.getIssuer().setValue(issuer);
    authnRequest.setNameIDPolicy(new NameIDPolicyType());
    authnRequest.getNameIDPolicy().setAllowCreate(false);
    authnRequest.setID(id);

    try {
      GregorianCalendar gregorianCalendar = GregorianCalendar.from(ZonedDateTime.now());
      XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(gregorianCalendar);
      authnRequest.setIssueInstant(now);
      authnRequest.setVersion("2.0");

      byte[] rawResult = marshall(new ObjectFactory().createAuthnRequest(authnRequest));
      String encodedResult = deflateAndEncode(rawResult);
      String parameters = "SAMLRequest=" + URLEncoder.encode(encodedResult, "UTF-8");
      if (relayState != null) {
        parameters += "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");
      }

      if (sign && key != null && algorithm != null) {
        Signature signature;
        parameters += "&SigAlg=" + URLEncoder.encode(algorithm.url, "UTF-8");
        signature = Signature.getInstance(algorithm.name);
        signature.initSign(key);
        signature.update(parameters.getBytes(StandardCharsets.UTF_8));

        String signatureParameter = Base64.getEncoder().encodeToString(signature.sign());
        parameters += "&Signature=" + URLEncoder.encode(signatureParameter, "UTF-8");
      }

      return parameters;
    } catch (Exception e) {
      // Not possible but freak out
      throw new SAMLException(e);
    }
  }

  @Override
  public AuthenticationResponse parseResponse(String encodedResponse, boolean verifySignature, PublicKey key)
      throws SAMLException {
    byte[] decodedResponse = Base64.getDecoder().decode(encodedResponse);
    Document document = parseFromBytes(decodedResponse);
    if (verifySignature) {
      verifySignature(document, key);
    }

    AuthenticationResponse response = new AuthenticationResponse();
    ResponseType jaxbResponse = unmarshallFromDocument(document);
    response.status = ResponseStatus.fromSAMLFormat(jaxbResponse.getStatus().getStatusCode().getValue());
    response.id = jaxbResponse.getID();
    response.issuer = jaxbResponse.getIssuer() != null ? jaxbResponse.getIssuer().getValue() : null;
    response.instant = toZonedDateTime(jaxbResponse.getIssueInstant());
    response.destination = jaxbResponse.getDestination();

    List<Object> assertions = jaxbResponse.getAssertionOrEncryptedAssertion();
    for (Object assertion : assertions) {
      if (assertion instanceof EncryptedElementType) {
        logger.warn("SAML response contained encrypted attribute. It was ignored.");
        continue;
      }

      AssertionType assertionType = (AssertionType) assertion;

      // Handle the subject
      SubjectType subject = assertionType.getSubject();
      if (subject != null) {
        List<JAXBElement<?>> elements = subject.getContent();
        for (JAXBElement<?> element : elements) {
          Class<?> type = element.getDeclaredType();
          if (type == NameIDType.class) {
            if (response.user != null) {
              logger.warn("SAML response contained multiple NameID elements. Only the first one was used.");
              continue;
            }

            // Extract the name
            response.user = parseUser((NameIDType) element.getValue());
          } else if (type == SubjectConfirmationType.class) {
            // Extract the confirmation
            response.confirmation = parseConfirmation((SubjectConfirmationType) element.getValue());
          } else if (type == EncryptedElementType.class) {
            throw new SAMLException("This library currently doesn't handle encrypted assertions");
          }
        }
      }

      // Handle conditions to pull out audience restriction
      ConditionsType conditionsType = assertionType.getConditions();
      response.notBefore = convertToZonedDateTime(conditionsType.getNotBefore());
      response.notOnOrAfter = convertToZonedDateTime(conditionsType.getNotOnOrAfter());

      List<ConditionAbstractType> conditionAbstractTypes = conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse();
      for (ConditionAbstractType conditionAbstractType : conditionAbstractTypes) {
        if (conditionAbstractType instanceof AudienceRestrictionType) {
          AudienceRestrictionType restrictionType = (AudienceRestrictionType) conditionAbstractType;
          response.audiences.addAll(restrictionType.getAudience());
        } else if (conditionAbstractType instanceof OneTimeUseType) {
          response.oneTimeUse = true;
        } else if (conditionAbstractType instanceof ProxyRestrictionType) {
          ProxyRestrictionType proxyRestrictionType = (ProxyRestrictionType) conditionAbstractType;
          response.proxyAudiences.addAll(proxyRestrictionType.getAudience());
          response.proxyCount = proxyRestrictionType.getCount() == null ? null : proxyRestrictionType.getCount().intValue();
        }
      }

      // Handle the attributes
      List<StatementAbstractType> statements = assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement();
      for (StatementAbstractType statement : statements) {
        if (statement instanceof AttributeStatementType) {
          AttributeStatementType attributeStatementType = (AttributeStatementType) statement;
          List<Object> attributeObjects = attributeStatementType.getAttributeOrEncryptedAttribute();
          for (Object attributeObject : attributeObjects) {
            if (attributeObject instanceof AttributeType) {
              AttributeType attributeType = (AttributeType) attributeObject;
              String name = attributeType.getName();
              List<Object> attributeValues = attributeType.getAttributeValue();
              List<String> values = attributeValues.stream().map(this::attributeToString).collect(Collectors.toList());
              response.user.attributes.computeIfAbsent(name, k -> new ArrayList<>()).addAll(values);
            } else {
              throw new SAMLException("This library currently doesn't support encrypted attributes");
            }
          }
        }
      }
    }

    return response;
  }

  private String attributeToString(Object attribute) {
    if (attribute instanceof Number) {
      return attribute.toString();
    } else if (attribute instanceof String) {
      return (String) attribute;
    } else if (attribute instanceof Element) {
      return ((Element) attribute).getTextContent();
    } else {
      logger.warn("This library currently doesn't handle attributes of type [" + attribute.getClass() + "]");
    }

    return null;
  }

  private ZonedDateTime convertToZonedDateTime(XMLGregorianCalendar cal) {
    return cal != null ? cal.toGregorianCalendar().toZonedDateTime() : null;
  }

  private String deflateAndEncode(byte[] result) {
    Deflater deflater = new Deflater(Deflater.DEFLATED, true);
    deflater.setInput(result);
    deflater.finish();
    byte[] deflatedResult = new byte[result.length];
    int length = deflater.deflate(deflatedResult);
    deflater.end();
    byte[] src = Arrays.copyOf(deflatedResult, length);
    return Base64.getEncoder().encodeToString(src);
  }

  private void fixIDs(Element element) {
    NamedNodeMap attributes = element.getAttributes();
    for (int i = 0; i < attributes.getLength(); i++) {
      Attr attribute = (Attr) attributes.item(i);
      if (attribute.getLocalName().toLowerCase().equals("id")) {
        element.setIdAttributeNode(attribute, true);
      }
    }

    NodeList children = element.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      if (child.getNodeType() == Node.ELEMENT_NODE) {
        fixIDs((Element) child);
      }
    }
  }

  private <T> byte[] marshall(T object) throws SAMLException {
    try {
      JAXBContext context = JAXBContext.newInstance(AuthnRequestType.class);
      Marshaller marshaller = context.createMarshaller();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      marshaller.marshal(object, baos);
      return baos.toByteArray();
    } catch (JAXBException e) {
      // Rethrow as runtime
      throw new SAMLException("Unable to marshall JAXB SAML object to DOM for signing.", e);
    }
  }

  private UserConfirmation parseConfirmation(SubjectConfirmationType subjectConfirmationType) {
    UserConfirmation userConfirmation = new UserConfirmation();
    SubjectConfirmationDataType data = subjectConfirmationType.getSubjectConfirmationData();
    if (data != null) {
      userConfirmation.address = data.getAddress();
      userConfirmation.inResponseTo = data.getInResponseTo();
      userConfirmation.notBefore = toZonedDateTime(data.getNotBefore());
      userConfirmation.notOnOrAfter = toZonedDateTime(data.getNotOnOrAfter());
      userConfirmation.recipient = data.getRecipient();
    }

    userConfirmation.method = ConfirmationMethod.fromSAMLFormat(subjectConfirmationType.getMethod());

    return userConfirmation;
  }

  private Document parseFromBytes(byte[] bytes) throws SAMLException {
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);
    try {
      DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
      return builder.parse(new ByteArrayInputStream(bytes));
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new SAMLException("Unable to parse SAML v2.0 authentication response", e);
    }
  }

  private User parseUser(NameIDType nameID) {
    NameIDFormat format = NameIDFormat.fromSAMLFormat(nameID.getFormat());
    String qualifier = nameID.getNameQualifier();
    String spQualifier = nameID.getSPNameQualifier();
    String spProviderID = nameID.getSPProvidedID();
    String id = nameID.getValue();
    return new User(format, id, qualifier, spProviderID, spQualifier);
  }

  private ZonedDateTime toZonedDateTime(XMLGregorianCalendar instant) {
    if (instant == null) {
      return null;
    }

    return instant.toGregorianCalendar().toZonedDateTime();
  }

  @SuppressWarnings("unchecked")
  private <T> T unmarshallFromDocument(Document document) throws SAMLException {
    try {
      JAXBContext context = JAXBContext.newInstance(ResponseType.class);
      Unmarshaller unmarshaller = context.createUnmarshaller();
      JAXBElement element = (JAXBElement) unmarshaller.unmarshal(document);
      return (T) element.getValue();
    } catch (JAXBException e) {
      throw new SAMLException("Unable to unmarshall SAML response", e);
    }
  }

  private void verifySignature(Document document, Key key) throws SAMLException {
    // Fix the IDs in the entire document per the suggestions at http://stackoverflow.com/questions/17331187/xml-dig-sig-error-after-upgrade-to-java7u25
    fixIDs(document.getDocumentElement());

    NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0) {
      return;
    }

    for (int i = 0; i < nl.getLength(); i++) {
      DOMValidateContext validateContext = new DOMValidateContext(key, nl.item(i));
      XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
      try {
        XMLSignature signature = factory.unmarshalXMLSignature(validateContext);
        boolean valid = signature.validate(validateContext);
        if (!valid) {
          throw new SAMLException("Invalid SAML v2.0 authentication response. The signature is invalid.");
        }
      } catch (MarshalException e) {
        throw new SAMLException("Unable to verify XML signature in the SAML v2.0 authentication response because we couldn't unmarshall the XML Signature element", e);
      } catch (XMLSignatureException e) {
        throw new SAMLException("Unable to verify XML signature in the SAML v2.0 authentication response. The signature was unmarshalled we couldn't validate it for an unknown reason", e);
      }
    }
  }
}
