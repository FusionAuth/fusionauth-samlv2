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
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
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
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.ConfirmationMethod;
import io.fusionauth.samlv2.domain.MetaData;
import io.fusionauth.samlv2.domain.NameIDFormat;
import io.fusionauth.samlv2.domain.ResponseStatus;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.User;
import io.fusionauth.samlv2.domain.UserConfirmation;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AssertionType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AttributeStatementType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AttributeType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AudienceRestrictionType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AuthnContextType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.AuthnStatementType;
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
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.EndpointType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.EntityDescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.IDPSSODescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.KeyDescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.KeyTypes;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.RoleDescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.NameIDPolicyType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.ObjectFactory;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.ResponseType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.StatusCodeType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.StatusType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.KeyInfoType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.X509DataType;
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
 * Default implementation of the SAML service.
 *
 * @author Brian Pontarelli
 */
public class DefaultSAMLv2Service implements SAMLv2Service {
  private static final io.fusionauth.samlv2.domain.jaxb.oasis.assertion.ObjectFactory ASSERTION_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.oasis.assertion.ObjectFactory();

  private static final io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.ObjectFactory DSIG_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.ObjectFactory();

  private static final io.fusionauth.samlv2.domain.jaxb.oasis.metadata.ObjectFactory METADATA_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.oasis.metadata.ObjectFactory();

  private static final ObjectFactory PROTOCOL_OBJECT_FACTORY = new ObjectFactory();

  private static final Logger logger = LoggerFactory.getLogger(DefaultSAMLv2Service.class);

  @Override
  public String buildAuthnResponse(AuthenticationResponse response, boolean sign, PublicKey publicKey,
                                   PrivateKey privateKey, Algorithm algorithm) throws SAMLException {
    ResponseType jaxbResponse = new ResponseType();

    // Status (element - order safe)
    StatusType status = new StatusType();
    status.setStatusCode(new StatusCodeType());
    status.getStatusCode().setValue(response.status.code.toSAMLFormat());
    status.setStatusMessage(response.status.message);
    jaxbResponse.setStatus(status);

    // Id (attribute), issuer (element - order safe) and version (attribute)
    jaxbResponse.setID(response.id);
    jaxbResponse.setIssuer(new NameIDType());
    jaxbResponse.getIssuer().setValue(response.issuer);
    jaxbResponse.setVersion(response.version);

    // Response to (attribute)
    jaxbResponse.setInResponseTo(response.inResponseTo);

    // Instant (attribute)
    jaxbResponse.setIssueInstant(toXMLGregorianCalendar(response.instant));

    // Destination (Attribute)
    jaxbResponse.setDestination(response.destination);

    // The main assertion element (element  - order safe)
    AssertionType assertionType = new AssertionType();
    if (response.user != null && response.status.code == ResponseStatus.Success) {
      ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
      String id = "_" + UUID.randomUUID().toString();
      assertionType.setID(id);
      assertionType.setIssuer(jaxbResponse.getIssuer());
      assertionType.setIssueInstant(toXMLGregorianCalendar(now));
      assertionType.setVersion(response.version);

      // NameId
      SubjectType subjectType = new SubjectType();
      NameIDType nameIdType = new NameIDType();
      nameIdType.setValue(response.user.id);
      nameIdType.setFormat(response.user.format.toSAMLFormat());
      nameIdType.setNameQualifier(response.user.qualifier);
      nameIdType.setSPNameQualifier(response.user.spQualifier);
      nameIdType.setSPProvidedID(response.user.spProviderID);
      subjectType.getContent().add(ASSERTION_OBJECT_FACTORY.createNameID(nameIdType));

      // Subject confirmation
      if (response.confirmation != null) {
        SubjectConfirmationDataType dataType = new SubjectConfirmationDataType();
        dataType.setAddress(response.confirmation.address);
        dataType.setInResponseTo(response.confirmation.inResponseTo);
        dataType.setNotBefore(toXMLGregorianCalendar(response.confirmation.notBefore));
        dataType.setNotOnOrAfter(toXMLGregorianCalendar(response.confirmation.notOnOrAfter));
        dataType.setRecipient(response.confirmation.recipient);
        SubjectConfirmationType subjectConfirmationType = new SubjectConfirmationType();
        subjectConfirmationType.setSubjectConfirmationData(dataType);
        if (response.confirmation.method != null) {
          subjectConfirmationType.setMethod(response.confirmation.method.toSAMLFormat());
        }
        subjectType.getContent().add(ASSERTION_OBJECT_FACTORY.createSubjectConfirmation(subjectConfirmationType));
      }

      // Add the subject
      assertionType.setSubject(subjectType);

      // Conditions
      ConditionsType conditionsType = new ConditionsType();
      conditionsType.setNotBefore(toXMLGregorianCalendar(response.notBefore));
      conditionsType.setNotOnOrAfter(toXMLGregorianCalendar(response.notOnOrAfter));
      assertionType.setConditions(conditionsType);

      // Audiences
      if (response.audiences.size() > 0) {
        AudienceRestrictionType audienceRestrictionType = new AudienceRestrictionType();
        audienceRestrictionType.getAudience().addAll(response.audiences);
        conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse().add(audienceRestrictionType);
      }

      // OneTimeUse
      if (response.oneTimeUse) {
        OneTimeUseType oneTimeUseType = new OneTimeUseType();
        conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse().add(oneTimeUseType);
      }

      // Proxy
      if (response.proxyAudiences.size() > 0 || response.proxyCount != null) {
        ProxyRestrictionType proxyRestrictionType = new ProxyRestrictionType();
        proxyRestrictionType.setCount(response.proxyCount != null ? BigInteger.valueOf(response.proxyCount) : null);
        proxyRestrictionType.getAudience().addAll(response.proxyAudiences);
        conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse().add(proxyRestrictionType);
      }

      // Attributes
      AttributeStatementType attributeStatementType = new AttributeStatementType();
      response.user.attributes.forEach((k, v) -> {
        AttributeType attributeType = new AttributeType();
        attributeType.setName(k);
        attributeType.getAttributeValue().addAll(v);
        attributeStatementType.getAttributeOrEncryptedAttribute().add(attributeType);
      });
      assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attributeStatementType);

      // AuthnStatement
      AuthnStatementType authnStatement = new AuthnStatementType();
      authnStatement.setAuthnInstant(toXMLGregorianCalendar(now));
      authnStatement.setAuthnContext(new AuthnContextType());
      authnStatement.getAuthnContext().getContent().add(ASSERTION_OBJECT_FACTORY.createAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
      assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(authnStatement);

      // Add the assertion (element - order doesn't matter)
      jaxbResponse.getAssertionOrEncryptedAssertion().add(assertionType);
    }

    Document document = marshallToDocument(PROTOCOL_OBJECT_FACTORY.createResponse(jaxbResponse), ResponseType.class);
    try {
      // If successful, sign the assertion. Otherwise, sign the root
      Element toSign;
      Node insertBefore;
      if (response.status.code == ResponseStatus.Success) {
        toSign = (Element) document.getElementsByTagName("Assertion").item(0);
        insertBefore = toSign.getElementsByTagName("Subject").item(0);
      } else {
        toSign = document.getDocumentElement();
        insertBefore = null;
      }

      // Set the id attribute node. Yucky! Yuck!
      toSign.setIdAttributeNode(toSign.getAttributeNode("ID"), true);

      // If there is an insert before, set it so that the signature is in the place that some IdPs require
      DOMSignContext dsc = new DOMSignContext(privateKey, toSign);
      if (insertBefore != null) {
        dsc.setNextSibling(insertBefore);
      }

      // Sign away
      XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
      Reference ref = factory.newReference("#" + toSign.getAttribute("ID"),
          factory.newDigestMethod(DigestMethod.SHA256, null),
          Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
          null,
          null);
      SignedInfo si = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null),
          factory.newSignatureMethod(algorithm.uri, null),
          Collections.singletonList(ref));
      KeyInfoFactory kif = factory.getKeyInfoFactory();
      KeyValue kv = kif.newKeyValue(publicKey);
      KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
      XMLSignature signature = factory.newXMLSignature(si, ki);

      signature.sign(dsc);

      StringWriter sw = new StringWriter();
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer transformer = tf.newTransformer();
      transformer.transform(new DOMSource(document), new StreamResult(sw));
      String xml = sw.toString();
      return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new SAMLException("Unable to sign XML SAML response", e);
    }
  }

  @Override
  public String buildHTTPRedirectAuthnRequest(String id, String issuer, String relayState, boolean sign, PrivateKey key,
                                              Algorithm algorithm)
      throws SAMLException {
    return _buildAuthnRequest(id, issuer, "2.0", relayState, sign, key, algorithm);
  }

  @Override
  public String buildInvalidTestingHTTPRedirectAuthnRequest(String id, String issuer, String relayState, boolean sign,
                                                            PrivateKey key, Algorithm algorithm) throws SAMLException {
    return _buildAuthnRequest(id, issuer, "bad", relayState, sign, key, algorithm);
  }

  @Override
  public String buildMetadataResponse(MetaData metaData) throws SAMLException {
    EntityDescriptorType root = new EntityDescriptorType();
    root.setID(metaData.id);
    root.setEntityID(metaData.entityId);

    IDPSSODescriptorType idp = new IDPSSODescriptorType();
    if (metaData.idp.signInEndpoint != null) {
      EndpointType signIn = new EndpointType();
      signIn.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
      signIn.setLocation(metaData.idp.signInEndpoint);
      idp.getSingleSignOnService().add(signIn);
    }

    if (metaData.idp.logoutEndpoint != null) {
      EndpointType logout = new EndpointType();
      logout.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
      logout.setLocation(metaData.idp.logoutEndpoint);
      idp.getSingleLogoutService().add(logout);
    }

    metaData.idp.certificates.forEach(cert -> {
      KeyDescriptorType key = new KeyDescriptorType();
      key.setUse(KeyTypes.SIGNING);
      KeyInfoType info = new KeyInfoType();
      key.setKeyInfo(info);
      X509DataType data = new X509DataType();
      info.getContent().add(DSIG_OBJECT_FACTORY.createX509Data(data));

      try {
        JAXBElement<byte[]> certElement = DSIG_OBJECT_FACTORY.createX509DataTypeX509Certificate(cert.getEncoded());
        data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(certElement);
        idp.getKeyDescriptor().add(key);
      } catch (Exception e) {
        // Rethrow
        throw new IllegalArgumentException(e);
      }
    });

    root.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(idp);

    // Convert to String
    byte[] bytes = marshallToBytes(METADATA_OBJECT_FACTORY.createEntityDescriptor(root), EntityDescriptorType.class);
    return new String(bytes, StandardCharsets.UTF_8);
  }

  @Override
  public MetaData parseMetaData(String metaDataXML) throws SAMLException {
    Document document = parseFromBytes(metaDataXML.getBytes(StandardCharsets.UTF_8));
    EntityDescriptorType root = unmarshallFromDocument(document, EntityDescriptorType.class);
    MetaData metaData = new MetaData();
    metaData.id = root.getID();
    metaData.entityId = root.getEntityID();

    List<RoleDescriptorType> roles = root.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor();
    Optional<RoleDescriptorType> optional = roles.stream()
                                                 .filter(r -> r instanceof IDPSSODescriptorType)
                                                 .findFirst();
    if (!optional.isPresent()) {
      return metaData;
    }

    IDPSSODescriptorType idp = (IDPSSODescriptorType) optional.get();

    // Extract the URLs
    metaData.idp.signInEndpoint = idp.getSingleSignOnService().size() > 0 ? idp.getSingleSignOnService().get(0).getLocation() : null;
    metaData.idp.logoutEndpoint = idp.getSingleLogoutService().size() > 0 ? idp.getSingleLogoutService().get(0).getLocation() : null;

    // Extract the signing certificates
    try {
      metaData.idp.certificates = idp.getKeyDescriptor()
                                     .stream()
                                     .filter(kd -> kd.getUse() == KeyTypes.SIGNING)
                                     .map(this::toCertificate)
                                     .filter(Objects::nonNull)
                                     .collect(Collectors.toList());
    } catch (IllegalArgumentException e) {
      // toPublicKey might throw this and we want to translate it back to a known exception
      throw new SAMLException(e.getCause());
    }

    return metaData;
  }

  @Override
  public AuthenticationRequest parseRequest(String encodedRequest, String relayState, String signature,
                                            boolean verifySignature, PublicKey key, Algorithm algorithm)
      throws SAMLException {
    byte[] requestBytes = decodeAndInflate(encodedRequest);
    Document document = parseFromBytes(requestBytes);
    AuthnRequestType authnRequest = unmarshallFromDocument(document, AuthnRequestType.class);
    AuthenticationRequest result = new AuthenticationRequest();
    result.id = authnRequest.getID();
    result.issuer = authnRequest.getIssuer().getValue();
    result.issueInstant = authnRequest.getIssueInstant().toGregorianCalendar().toZonedDateTime();
    result.nameIdFormat = NameIDFormat.fromSAMLFormat(authnRequest.getNameIDPolicy().getFormat());
    result.version = authnRequest.getVersion();

    if (verifySignature) {
      if (signature == null || key == null || algorithm == null) {
        throw new NullPointerException("You must specify a signature, key and algorithm if you want to verify the SAML request signature");
      }

      try {
        String parameters = "SAMLRequest=" + URLEncoder.encode(encodedRequest, "UTF-8");
        if (relayState != null) {
          parameters += "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");
        }
        parameters += "&SigAlg=" + URLEncoder.encode(algorithm.uri, "UTF-8");

        Signature sig = Signature.getInstance(algorithm.name);
        sig.initVerify(key);
        sig.update(parameters.getBytes(StandardCharsets.UTF_8));
        if (!sig.verify(Base64.getDecoder().decode(signature))) {
          throw new SAMLException("Invalid signature");
        }
      } catch (Exception e) {
        throw new SAMLException("Unable to verify signature", e);
      }
    }

    return result;
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
    ResponseType jaxbResponse = unmarshallFromDocument(document, ResponseType.class);
    response.status.code = ResponseStatus.fromSAMLFormat(jaxbResponse.getStatus().getStatusCode().getValue());
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

  private String _buildAuthnRequest(String id, String issuer, String version, String relayState, boolean sign,
                                    PrivateKey key,
                                    Algorithm algorithm) throws SAMLException {
    // SAML Web SSO profile requirements (section 4.1.4.1)
    AuthnRequestType authnRequest = new AuthnRequestType();
    authnRequest.setIssuer(new NameIDType());
    authnRequest.getIssuer().setValue(issuer);
    authnRequest.setNameIDPolicy(new NameIDPolicyType());
    authnRequest.getNameIDPolicy().setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
    authnRequest.getNameIDPolicy().setAllowCreate(false);
    authnRequest.setID(id);
    authnRequest.setVersion(version);
    authnRequest.setIssueInstant(new XMLGregorianCalendarImpl(GregorianCalendar.from(ZonedDateTime.now())));

    try {
      byte[] rawResult = marshallToBytes(PROTOCOL_OBJECT_FACTORY.createAuthnRequest(authnRequest), AuthnRequestType.class);
      String encodedResult = deflateAndEncode(rawResult);
      String parameters = "SAMLRequest=" + URLEncoder.encode(encodedResult, "UTF-8");
      if (relayState != null) {
        parameters += "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");
      }

      if (sign && key != null && algorithm != null) {
        Signature signature;
        parameters += "&SigAlg=" + URLEncoder.encode(algorithm.uri, "UTF-8");
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

  private byte[] decodeAndInflate(String encodedRequest) throws SAMLException {
    byte[] bytes = Base64.getDecoder().decode(encodedRequest);
    Inflater inflater = new Inflater(true);
    inflater.setInput(bytes);
    inflater.finished();

    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      byte[] result = new byte[bytes.length];
      while (!inflater.finished()) {
        int length = inflater.inflate(result);
        if (length > 0) {
          baos.write(result, 0, length);
        }
      }

      return baos.toByteArray();
    } catch (DataFormatException e) {
      throw new SAMLException("Invalid AuthnRequest. Inflating the bytes failed.", e);
    }
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

  private <T> byte[] marshallToBytes(JAXBElement<T> object, Class<T> type) throws SAMLException {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Marshaller marshaller = context.createMarshaller();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      marshaller.marshal(object, baos);
      return baos.toByteArray();
    } catch (JAXBException e) {
      throw new SAMLException("Unable to marshallRequest JAXB SAML object to bytes.", e);
    }
  }

  @SuppressWarnings("SameParameterValue")
  private <T> Document marshallToDocument(JAXBElement<T> object, Class<T> type) throws SAMLException {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Marshaller marshaller = context.createMarshaller();
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      DocumentBuilder db = dbf.newDocumentBuilder();
      Document document = db.newDocument();
      marshaller.marshal(object, document);
      return document;
    } catch (JAXBException | ParserConfigurationException e) {
      throw new SAMLException("Unable to marshallRequest JAXB SAML object to DOM.", e);
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

  private Certificate toCertificate(KeyDescriptorType keyDescriptorType) {
    try {
      List<Object> keyData = keyDescriptorType.getKeyInfo().getContent();
      for (Object keyDatum : keyData) {
        if (keyDatum instanceof JAXBElement<?>) {
          JAXBElement<?> element = (JAXBElement<?>) keyDatum;
          if (element.getDeclaredType() == X509DataType.class) {
            X509DataType cert = (X509DataType) element.getValue();
            List<Object> certData = cert.getX509IssuerSerialOrX509SKIOrX509SubjectName();
            for (Object certDatum : certData) {
              element = (JAXBElement<?>) certDatum;
              if (element.getName().getLocalPart().equals("X509Certificate")) {
                byte[] certBytes = (byte[]) element.getValue();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return cf.generateCertificate(new ByteArrayInputStream(certBytes));
              }
            }
          }
        }
      }

      return null;
    } catch (CertificateException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private XMLGregorianCalendar toXMLGregorianCalendar(ZonedDateTime instant) {
    if (instant == null) {
      return null;
    }

    return new XMLGregorianCalendarImpl(GregorianCalendar.from(instant));
  }

  private ZonedDateTime toZonedDateTime(XMLGregorianCalendar instant) {
    if (instant == null) {
      return null;
    }

    return instant.toGregorianCalendar().toZonedDateTime();
  }

  private <T> T unmarshallFromDocument(Document document, Class<T> type) throws SAMLException {
    try {
      JAXBContext context = JAXBContext.newInstance(type);
      Unmarshaller unmarshaller = context.createUnmarshaller();
      JAXBElement<T> element = unmarshaller.unmarshal(document, type);
      return element.getValue();
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
