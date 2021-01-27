/*
 * Copyright (c) 2013-2019, Inversoft Inc., All Rights Reserved
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
import javax.xml.crypto.KeySelector;
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
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.Binding;
import io.fusionauth.samlv2.domain.Conditions;
import io.fusionauth.samlv2.domain.ConfirmationMethod;
import io.fusionauth.samlv2.domain.MetaData;
import io.fusionauth.samlv2.domain.MetaData.IDPMetaData;
import io.fusionauth.samlv2.domain.MetaData.SPMetaData;
import io.fusionauth.samlv2.domain.NameID;
import io.fusionauth.samlv2.domain.NameIDFormat;
import io.fusionauth.samlv2.domain.ResponseStatus;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.SignatureLocation;
import io.fusionauth.samlv2.domain.SignatureNotFoundException;
import io.fusionauth.samlv2.domain.Subject;
import io.fusionauth.samlv2.domain.SubjectConfirmation;
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
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.StatementAbstractType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.SubjectConfirmationDataType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.SubjectConfirmationType;
import io.fusionauth.samlv2.domain.jaxb.oasis.assertion.SubjectType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.EndpointType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.EntityDescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.IDPSSODescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.IndexedEndpointType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.KeyDescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.KeyTypes;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.RoleDescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.SPSSODescriptorType;
import io.fusionauth.samlv2.domain.jaxb.oasis.metadata.SSODescriptorType;
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

  static {
    String ignoreLineBreaks = System.getProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks");
    if (!Boolean.parseBoolean(ignoreLineBreaks)) {
      throw new IllegalStateException("When the fusionauth-samlv2 jar is included in the classpath, you must set the following system property:\n" +
          "-Dcom.sun.org.apache.xml.internal.security.ignoreLineBreaks=true");
    }
  }

  @Override
  public String buildAuthnResponse(AuthenticationResponse response, boolean sign, PrivateKey privateKey,
                                   X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod,
                                   SignatureLocation signatureOption) throws SAMLException {
    ResponseType jaxbResponse = new ResponseType();

    // Status (element)
    StatusType status = new StatusType();
    status.setStatusCode(new StatusCodeType());
    status.getStatusCode().setValue(response.status.code.toSAMLFormat());
    status.setStatusMessage(response.status.message);
    jaxbResponse.setStatus(status);

    // Id (attribute), issuer (element) and version (attribute)
    jaxbResponse.setID(response.id);
    jaxbResponse.setIssuer(new NameIDType());
    jaxbResponse.getIssuer().setValue(response.issuer);
    jaxbResponse.setVersion(response.version);

    // Response to (attribute)
    jaxbResponse.setInResponseTo(response.inResponseTo);

    // Instant (attribute)
    jaxbResponse.setIssueInstant(toXMLGregorianCalendar(response.issueInstant));

    // Destination (Attribute)
    jaxbResponse.setDestination(response.destination);

    // The main assertion (element)
    AssertionType assertionType = new AssertionType();
    if (response.assertion != null && response.status.code == ResponseStatus.Success) {
      ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
      String id = "_" + UUID.randomUUID().toString();
      assertionType.setID(id);
      assertionType.setIssuer(jaxbResponse.getIssuer());
      assertionType.setIssueInstant(toXMLGregorianCalendar(now));
      assertionType.setVersion(response.version);

      // Subject (element)
      if (response.assertion.subject != null) {
        SubjectType subjectType = new SubjectType();

        // NameId (element)
        if (response.assertion.subject.nameID != null) {
          NameIDType nameIdType = new NameIDType();
          nameIdType.setValue(response.assertion.subject.nameID.id);
          nameIdType.setFormat(response.assertion.subject.nameID.format.toSAMLFormat());
          subjectType.getContent().add(ASSERTION_OBJECT_FACTORY.createNameID(nameIdType));
        }

        // Subject confirmation (element)
        if (response.assertion.subject.subjectConfirmation != null) {
          SubjectConfirmationDataType dataType = new SubjectConfirmationDataType();
          dataType.setInResponseTo(response.assertion.subject.subjectConfirmation.inResponseTo);
          dataType.setNotBefore(toXMLGregorianCalendar(response.assertion.subject.subjectConfirmation.notBefore));
          dataType.setNotOnOrAfter(toXMLGregorianCalendar(response.assertion.subject.subjectConfirmation.notOnOrAfter));
          dataType.setRecipient(response.assertion.subject.subjectConfirmation.recipient);
          SubjectConfirmationType subjectConfirmationType = new SubjectConfirmationType();
          subjectConfirmationType.setSubjectConfirmationData(dataType);
          if (response.assertion.subject.subjectConfirmation.method != null) {
            subjectConfirmationType.setMethod(response.assertion.subject.subjectConfirmation.method.toSAMLFormat());
          }
          subjectType.getContent().add(ASSERTION_OBJECT_FACTORY.createSubjectConfirmation(subjectConfirmationType));
        }

        // Add the subject
        assertionType.setSubject(subjectType);
      }

      // Conditions (element)
      if (response.assertion.conditions != null) {
        ConditionsType conditionsType = new ConditionsType();
        conditionsType.setNotBefore(toXMLGregorianCalendar(response.assertion.conditions.notBefore));
        conditionsType.setNotOnOrAfter(toXMLGregorianCalendar(response.assertion.conditions.notOnOrAfter));
        assertionType.setConditions(conditionsType);

        // Audiences (element)
        if (response.assertion.conditions.audiences.size() > 0) {
          AudienceRestrictionType audienceRestrictionType = new AudienceRestrictionType();
          audienceRestrictionType.getAudience().addAll(response.assertion.conditions.audiences);
          conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse().add(audienceRestrictionType);
        }
      }

      // Attributes (elements)
      AttributeStatementType attributeStatementType = new AttributeStatementType();
      response.assertion.attributes.forEach((k, v) -> {
        AttributeType attributeType = new AttributeType();
        attributeType.setName(k);
        attributeType.getAttributeValue().addAll(v);
        attributeStatementType.getAttributeOrEncryptedAttribute().add(attributeType);
      });
      assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(attributeStatementType);

      // AuthnStatement (element)
      AuthnStatementType authnStatement = new AuthnStatementType();
      authnStatement.setAuthnInstant(toXMLGregorianCalendar(now));
      authnStatement.setAuthnContext(new AuthnContextType());
      authnStatement.getAuthnContext().getContent().add(ASSERTION_OBJECT_FACTORY.createAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
      authnStatement.setSessionIndex(response.sessionIndex);
      authnStatement.setSessionNotOnOrAfter(toXMLGregorianCalendar(response.sessionExpiry));
      assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(authnStatement);

      // Add the assertion (element - order doesn't matter)
      jaxbResponse.getAssertionOrEncryptedAssertion().add(assertionType);
    }

    Document document = marshallToDocument(PROTOCOL_OBJECT_FACTORY.createResponse(jaxbResponse), ResponseType.class);
    try {
      // If successful, sign the assertion if requested, otherwise, sign the root
      Element toSign;
      Node insertBefore = null;
      // The 'Signature' must come directly after the 'Issuer' element.
      if (response.status.code == ResponseStatus.Success && signatureOption == SignatureLocation.Assertion) {
        toSign = (Element) document.getElementsByTagName("Assertion").item(0);
        // Issuer is the only required element. See schema for AssertionType in section 2.3.3 of SAML Core.
        // - The next sibling of the 'Issuer' may be null, this will cause the Signature to be inserted as the last element
        //   of the assertion which is what we want.
        Node issuer = toSign.getElementsByTagName("Issuer").item(0);
        insertBefore = issuer.getNextSibling();
      } else {
        toSign = document.getDocumentElement();
        // The only required element in the StatusResponseType is Status. See Section 3.2.2 in SAML Core.
        // The children will be a sequence that must exist in the order of 'Issuer', 'Signature', 'Extensions', and then 'Status'
        // - If the first element is 'Issuer', then the next sibling will be used for 'insertBefore'.
        // - If the first element is NOT 'Issuer', it MUST be 'Extensions' or 'Status', and thus is the 'insertBefore' node.
        NodeList children = toSign.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
          Node n = children.item(i);
          if (n instanceof Element) {
            insertBefore = n.getLocalName().equals("Issuer") ? n.getNextSibling() : n;
            break;
          }
        }
      }

      String xml = signXML(privateKey, certificate, algorithm, xmlSignatureC14nMethod, document, toSign, insertBefore);
      return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new SAMLException("Unable to sign XML SAML response", e);
    }
  }

  @Override
  public String buildInvalidTestingPostAuthnRequest(AuthenticationRequest request, boolean sign, PrivateKey privateKey,
                                                    X509Certificate certificate, Algorithm algorithm,
                                                    String xmlSignatureC14nMethod) throws SAMLException {
    AuthnRequestType authnRequest = toAuthnRequest(request, "bad");
    return buildPostAuthnRequest(authnRequest, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod);
  }

  @Override
  public String buildInvalidTestingRedirectAuthnRequest(AuthenticationRequest request, String relayState, boolean sign,
                                                        PrivateKey key, Algorithm algorithm) throws SAMLException {
    AuthnRequestType authnRequest = toAuthnRequest(request, "bad");
    return buildRedirectAuthnRequest(authnRequest, relayState, sign, key, algorithm);
  }

  @Override
  public String buildMetadataResponse(MetaData metaData) throws SAMLException {
    EntityDescriptorType root = new EntityDescriptorType();
    root.setID("_" + metaData.id);
    root.setEntityID(metaData.entityId);

    if (metaData.idp != null) {
      IDPSSODescriptorType idp = new IDPSSODescriptorType();
      idp.getProtocolSupportEnumeration().add("urn:oasis:names:tc:SAML:2.0:protocol");

      metaData.idp.redirectBindingSignInEndpoints.forEach(endpoint -> {
        EndpointType signIn = new EndpointType();
        signIn.setBinding(Binding.HTTP_Redirect.toSAMLFormat());
        signIn.setLocation(endpoint);
        idp.getSingleSignOnService().add(signIn);
      });

      metaData.idp.postBindingSignInEndpoints.forEach(endpoint -> {
        EndpointType signIn = new EndpointType();
        signIn.setBinding(Binding.HTTP_POST.toSAMLFormat());
        signIn.setLocation(endpoint);
        idp.getSingleSignOnService().add(signIn);
      });

      metaData.idp.redirectBindingLogoutEndpoints.forEach(endpoint -> {
        EndpointType logOut = new EndpointType();
        logOut.setBinding(Binding.HTTP_Redirect.toSAMLFormat());
        logOut.setLocation(endpoint);
        idp.getSingleLogoutService().add(logOut);
      });

      metaData.idp.postBindingLogoutEndpoints.forEach(endpoint -> {
        EndpointType logOut = new EndpointType();
        logOut.setBinding(Binding.HTTP_POST.toSAMLFormat());
        logOut.setLocation(endpoint);
        idp.getSingleLogoutService().add(logOut);
      });

      // Add certificates
      addKeyDescriptors(idp, metaData.idp.certificates);

      root.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(idp);
    }

    if (metaData.sp != null) {
      SPSSODescriptorType sp = new SPSSODescriptorType();
      sp.getProtocolSupportEnumeration().add("urn:oasis:names:tc:SAML:2.0:protocol");
      sp.setAuthnRequestsSigned(metaData.sp.authnRequestsSigned);
      sp.setWantAssertionsSigned(metaData.sp.wantAssertionsSigned);

      if (metaData.sp.acsEndpoint != null) {
        IndexedEndpointType acs = new IndexedEndpointType();
        acs.setBinding(Binding.HTTP_POST.toSAMLFormat());
        acs.setLocation(metaData.sp.acsEndpoint);
        sp.getAssertionConsumerService().add(acs);
      }

      if (metaData.sp.nameIDFormat != null) {
        sp.getNameIDFormat().add(metaData.sp.nameIDFormat.toSAMLFormat());
      }

      // Add certificates
      addKeyDescriptors(sp, metaData.sp.certificates);

      root.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(sp);
    }

    // Convert to String
    byte[] bytes = marshallToBytes(METADATA_OBJECT_FACTORY.createEntityDescriptor(root), EntityDescriptorType.class);
    return new String(bytes, StandardCharsets.UTF_8);
  }

  @Override
  public String buildPostAuthnRequest(AuthenticationRequest request, boolean sign, PrivateKey privateKey,
                                      X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod)
      throws SAMLException {
    AuthnRequestType authnRequest = toAuthnRequest(request, "2.0");
    return buildPostAuthnRequest(authnRequest, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod);
  }

  @Override
  public String buildRedirectAuthnRequest(AuthenticationRequest request, String relayState, boolean sign,
                                          PrivateKey key,
                                          Algorithm algorithm)
      throws SAMLException {
    AuthnRequestType authnRequest = toAuthnRequest(request, "2.0");
    return buildRedirectAuthnRequest(authnRequest, relayState, sign, key, algorithm);
  }

  @Override
  public MetaData parseMetaData(String metaDataXML) throws SAMLException {
    Document document = parseFromBytes(metaDataXML.getBytes(StandardCharsets.UTF_8));
    EntityDescriptorType root = unmarshallFromDocument(document, EntityDescriptorType.class);
    MetaData metaData = new MetaData();
    metaData.id = root.getID();
    metaData.entityId = root.getEntityID();

    List<RoleDescriptorType> roles = root.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor();
    Optional<RoleDescriptorType> idpDescriptor = roles.stream()
                                                      .filter(r -> r instanceof IDPSSODescriptorType)
                                                      .findFirst();
    if (idpDescriptor.isPresent()) {
      IDPSSODescriptorType idp = (IDPSSODescriptorType) idpDescriptor.get();

      // Extract the URLs
      metaData.idp = new IDPMetaData();

      // Extract SignIn URLs
      for (EndpointType endpoint : idp.getSingleSignOnService()) {
        if (Binding.HTTP_Redirect.toSAMLFormat().equals(endpoint.getBinding())) {
          metaData.idp.redirectBindingSignInEndpoints.add(endpoint.getLocation());
        } else if (Binding.HTTP_POST.toSAMLFormat().equals(endpoint.getBinding())) {
          metaData.idp.postBindingSignInEndpoints.add(endpoint.getLocation());
        }
      }

      // Extract Logout URLs
      for (EndpointType endpoint : idp.getSingleLogoutService()) {
        if (Binding.HTTP_Redirect.toSAMLFormat().equals(endpoint.getBinding())) {
          metaData.idp.redirectBindingLogoutEndpoints.add(endpoint.getLocation());
        } else if (Binding.HTTP_POST.toSAMLFormat().equals(endpoint.getBinding())) {
          metaData.idp.postBindingLogoutEndpoints.add(endpoint.getLocation());
        }
      }

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
    }

    Optional<RoleDescriptorType> spDescriptor = roles.stream()
                                                     .filter(r -> r instanceof SPSSODescriptorType)
                                                     .findFirst();

    if (spDescriptor.isPresent()) {
      SPSSODescriptorType sp = (SPSSODescriptorType) spDescriptor.get();
      metaData.sp = new SPMetaData();
      metaData.sp.acsEndpoint = sp.getAssertionConsumerService().size() > 0 ? sp.getAssertionConsumerService().get(0).getLocation() : null;
      try {
        metaData.sp.nameIDFormat = sp.getNameIDFormat().size() > 0 ? NameIDFormat.fromSAMLFormat(sp.getNameIDFormat().get(0)) : null;
      } catch (Exception e) {
        // fromSAMLFormat may throw an exception if the Name ID Format is not defined by our NameIDFormat enum.
        throw new SAMLException(e.getCause());
      }
    }

    return metaData;
  }

  @Override
  public AuthenticationRequest parseRequestPostBinding(String encodedRequest,
                                                       Function<AuthenticationRequest, PostBindingSignatureHelper> signatureHelperFunction)
      throws SAMLException {
    byte[] xml = Base64.getMimeDecoder().decode(encodedRequest);
    AuthnRequestParseResult result = parseRequest(xml);
    PostBindingSignatureHelper signatureHelper = signatureHelperFunction.apply(result.request);
    if (signatureHelper.verifySignature()) {
      verifySignature(result.document, signatureHelper.keySelector());
    }

    return result.request;
  }

  @Override
  public AuthenticationRequest parseRequestRedirectBinding(String encodedRequest, String relayState,
                                                           Function<AuthenticationRequest, RedirectBindingSignatureHelper> signatureHelperFunction)
      throws SAMLException {
    AuthnRequestParseResult result = parseRequest(decodeAndInflate(encodedRequest));
    RedirectBindingSignatureHelper signatureHelper = signatureHelperFunction.apply(result.request);
    if (signatureHelper.verifySignature()) {
      if (signatureHelper.signature() == null || signatureHelper.publicKey() == null || signatureHelper.algorithm() == null) {
        throw new SignatureNotFoundException("You must specify a signature, key and algorithm if you want to verify the SAML request signature");
      }

      try {
        String parameters = "SAMLRequest=" + URLEncoder.encode(encodedRequest, "UTF-8");
        if (relayState != null) {
          parameters += "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");
        }
        parameters += "&SigAlg=" + URLEncoder.encode(signatureHelper.algorithm().uri, "UTF-8");

        Signature sig = Signature.getInstance(signatureHelper.algorithm().name);
        sig.initVerify(signatureHelper.publicKey());
        sig.update(parameters.getBytes(StandardCharsets.UTF_8));
        if (!sig.verify(Base64.getMimeDecoder().decode(signatureHelper.signature()))) {
          throw new SAMLException("Invalid SAML v2.0 operation. The signature is invalid.");
        }
      } catch (GeneralSecurityException | UnsupportedEncodingException e) {
        throw new SAMLException("Unable to verify signature", e);
      }
    }

    return result.request;
  }

  @Override
  public AuthenticationResponse parseResponse(String encodedResponse, boolean verifySignature, KeySelector keySelector)
      throws SAMLException {

    AuthenticationResponse response = new AuthenticationResponse();
    byte[] decodedResponse = Base64.getMimeDecoder().decode(encodedResponse);
    response.rawResponse = new String(decodedResponse, StandardCharsets.UTF_8);

    Document document = parseFromBytes(decodedResponse);
    if (verifySignature) {
      verifySignature(document, keySelector);
    }

    ResponseType jaxbResponse = unmarshallFromDocument(document, ResponseType.class);
    response.status.code = ResponseStatus.fromSAMLFormat(jaxbResponse.getStatus().getStatusCode().getValue());
    response.id = jaxbResponse.getID();
    response.inResponseTo = jaxbResponse.getInResponseTo();
    response.issuer = jaxbResponse.getIssuer() != null ? jaxbResponse.getIssuer().getValue() : null;
    response.issueInstant = toZonedDateTime(jaxbResponse.getIssueInstant());
    response.destination = jaxbResponse.getDestination();
    response.version = jaxbResponse.getVersion();

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
        response.assertion.subject = new Subject();

        List<JAXBElement<?>> elements = subject.getContent();
        for (JAXBElement<?> element : elements) {
          Class<?> type = element.getDeclaredType();
          if (type == NameIDType.class) {
            if (response.assertion.subject.nameID != null) {
              logger.warn("SAML response contained multiple NameID elements. Only the first one was used.");
              continue;
            }

            // Extract the name
            response.assertion.subject.nameID = parseNameId((NameIDType) element.getValue());
          } else if (type == SubjectConfirmationType.class) {
            // Extract the confirmation
            response.assertion.subject.subjectConfirmation = parseConfirmation((SubjectConfirmationType) element.getValue());
          } else if (type == EncryptedElementType.class) {
            throw new SAMLException("This library currently doesn't handle encrypted assertions");
          }
        }
      }

      // Handle conditions to pull out audience restriction
      ConditionsType conditionsType = assertionType.getConditions();
      if (conditionsType != null) {
        response.assertion.conditions = new Conditions();
        response.assertion.conditions.notBefore = convertToZonedDateTime(conditionsType.getNotBefore());
        response.assertion.conditions.notOnOrAfter = convertToZonedDateTime(conditionsType.getNotOnOrAfter());

        List<ConditionAbstractType> conditionAbstractTypes = conditionsType.getConditionOrAudienceRestrictionOrOneTimeUse();
        // Only handling the AudienceRestriction.
        // - Optional additional conditions include OneTimeUse and ProxyRestriction.  See section 2.5.1 in the SAML v2 core spec,
        //   the way these additional conditions are described, I see no use for them.
        //   - OneTimeUse specifics are in section 2.5.1.5
        //   - ProxyRestriction specifics are in section 2.6.1.6
        //   http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
        for (ConditionAbstractType conditionAbstractType : conditionAbstractTypes) {
          if (conditionAbstractType instanceof AudienceRestrictionType) {
            AudienceRestrictionType restrictionType = (AudienceRestrictionType) conditionAbstractType;
            response.assertion.conditions.audiences.addAll(restrictionType.getAudience());
          }
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
              response.assertion.attributes.computeIfAbsent(name, k -> new ArrayList<>()).addAll(values);
            } else {
              throw new SAMLException("This library currently doesn't support encrypted attributes");
            }
          }
        }
      }
    }

    return response;
  }

  private void addKeyDescriptors(SSODescriptorType descriptor, List<Certificate> certificates) {
    certificates.forEach(cert -> {
      KeyDescriptorType key = new KeyDescriptorType();
      key.setUse(KeyTypes.SIGNING);
      KeyInfoType info = new KeyInfoType();
      key.setKeyInfo(info);
      X509DataType data = new X509DataType();
      info.getContent().add(DSIG_OBJECT_FACTORY.createX509Data(data));

      try {
        JAXBElement<byte[]> certElement = DSIG_OBJECT_FACTORY.createX509DataTypeX509Certificate(cert.getEncoded());
        data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(certElement);
        descriptor.getKeyDescriptor().add(key);
      } catch (Exception e) {
        // Rethrow
        throw new IllegalArgumentException(e);
      }
    });
  }

  private String attributeToString(Object attribute) {
    if (attribute == null) {
      return null;
    }

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

  private String buildPostAuthnRequest(AuthnRequestType authnRequest, boolean sign, PrivateKey privateKey,
                                       X509Certificate certificate,
                                       Algorithm algorithm, String xmlSignatureC14nMethod) throws SAMLException {
    Document document = marshallToDocument(PROTOCOL_OBJECT_FACTORY.createAuthnRequest(authnRequest), AuthnRequestType.class);
    try {
      Element toSign = document.getDocumentElement();
      String xml;
      if (sign) {
        xml = signXML(privateKey, certificate, algorithm, xmlSignatureC14nMethod, document, toSign, null);
      } else {
        xml = marshallToString(document);
      }

      return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new SAMLException("Unable to sign XML SAML response", e);
    }
  }

  private String buildRedirectAuthnRequest(AuthnRequestType authnRequest, String relayState, boolean sign,
                                           PrivateKey key, Algorithm algorithm) throws SAMLException {
    try {
      byte[] xml = marshallToBytes(PROTOCOL_OBJECT_FACTORY.createAuthnRequest(authnRequest), AuthnRequestType.class);
      String encodedResult = deflateAndEncode(xml);
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

  private ZonedDateTime convertToZonedDateTime(XMLGregorianCalendar cal) {
    return cal != null ? cal.toGregorianCalendar().toZonedDateTime() : null;
  }

  private byte[] decodeAndInflate(String encodedRequest) throws SAMLException {
    byte[] bytes = Base64.getMimeDecoder().decode(encodedRequest);
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
      if (attribute.getLocalName().equalsIgnoreCase("id")) {
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

  private String marshallToString(Document document) throws TransformerException {
    StringWriter sw = new StringWriter();
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer transformer = tf.newTransformer();
    transformer.transform(new DOMSource(document), new StreamResult(sw));
    return sw.toString();
  }

  private SubjectConfirmation parseConfirmation(SubjectConfirmationType subjectConfirmationType) {
    SubjectConfirmation subjectConfirmation = new SubjectConfirmation();
    SubjectConfirmationDataType data = subjectConfirmationType.getSubjectConfirmationData();
    if (data != null) {
      subjectConfirmation.address = data.getAddress();
      subjectConfirmation.inResponseTo = data.getInResponseTo();
      subjectConfirmation.notBefore = toZonedDateTime(data.getNotBefore());
      subjectConfirmation.notOnOrAfter = toZonedDateTime(data.getNotOnOrAfter());
      subjectConfirmation.recipient = data.getRecipient();
    }

    subjectConfirmation.method = ConfirmationMethod.fromSAMLFormat(subjectConfirmationType.getMethod());

    return subjectConfirmation;
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

  private NameID parseNameId(NameIDType element) {
    NameID nameId = new NameID();
    nameId.format = NameIDFormat.fromSAMLFormat(element.getFormat());
    nameId.id = element.getValue();
    return nameId;
  }

  private AuthnRequestParseResult parseRequest(byte[] xmlBytes) throws SAMLException {
    String xml = new String(xmlBytes, StandardCharsets.UTF_8);
    if (logger.isDebugEnabled()) {
      logger.debug("SAMLRequest XML is\n{}", xml);
    }

    AuthnRequestParseResult result = new AuthnRequestParseResult();
    result.document = parseFromBytes(xmlBytes);
    result.authnRequest = unmarshallFromDocument(result.document, AuthnRequestType.class);
    result.request = new AuthenticationRequest();
    result.request.xml = xml;
    result.request.id = result.authnRequest.getID();
    result.request.issuer = result.authnRequest.getIssuer().getValue();
    result.request.issueInstant = result.authnRequest.getIssueInstant().toGregorianCalendar().toZonedDateTime();
    NameIDPolicyType nameIdPolicyType = result.authnRequest.getNameIDPolicy();
    if (nameIdPolicyType == null) {
      result.request.nameIdFormat = NameIDFormat.EmailAddress;
    } else {
      result.request.nameIdFormat = NameIDFormat.fromSAMLFormat(nameIdPolicyType.getFormat());
    }
    result.request.version = result.authnRequest.getVersion();
    return result;
  }

  private String signXML(PrivateKey privateKey, X509Certificate certificate, Algorithm algorithm,
                         String xmlSignatureC14nMethod, Document document, Element toSign, Node insertBefore)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, TransformerException {
    // Set the id attribute node. Yucky! Yuck!
    toSign.setIdAttributeNode(toSign.getAttributeNode("ID"), true);

    // If there is an insert before, set it so that the signature is in the place that some IdPs require
    // - If insertBefore is 'null' the signature will be inserted as the last element.
    DOMSignContext dsc = new DOMSignContext(privateKey, toSign);
    dsc.setNextSibling(insertBefore);

    // Sign away
    XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
    CanonicalizationMethod c14n = factory.newCanonicalizationMethod(xmlSignatureC14nMethod, (C14NMethodParameterSpec) null);
    Reference ref = factory.newReference("#" + toSign.getAttribute("ID"),
        factory.newDigestMethod(DigestMethod.SHA256, null),
        Arrays.asList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null), c14n),
        null,
        null);
    SignedInfo si = factory.newSignedInfo(c14n,
        factory.newSignatureMethod(algorithm.uri, null),
        Collections.singletonList(ref));
    KeyInfoFactory kif = factory.getKeyInfoFactory();
    X509Data data = kif.newX509Data(Collections.singletonList(certificate));
    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(data));
    XMLSignature signature = factory.newXMLSignature(si, ki);

    signature.sign(dsc);
    return marshallToString(document);
  }

  private AuthnRequestType toAuthnRequest(AuthenticationRequest request, String version) {
    // SAML Web SSO profile requirements (section 4.1.4.1)
    AuthnRequestType authnRequest = new AuthnRequestType();
    authnRequest.setAssertionConsumerServiceURL(request.acsURL);
    authnRequest.setDestination(request.destination);
    authnRequest.setIssuer(new NameIDType());
    authnRequest.getIssuer().setValue(request.issuer);
    authnRequest.setNameIDPolicy(new NameIDPolicyType());
    authnRequest.getNameIDPolicy().setFormat(NameIDFormat.EmailAddress.toSAMLFormat());
    authnRequest.getNameIDPolicy().setAllowCreate(false);
    authnRequest.setID(request.id);
    authnRequest.setVersion(version);
    authnRequest.setIssueInstant(new XMLGregorianCalendarImpl(GregorianCalendar.from(ZonedDateTime.now())));
    return authnRequest;
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

  private void verifySignature(Document document, KeySelector keySelector) throws SAMLException {
    // Fix the IDs in the entire document per the suggestions at http://stackoverflow.com/questions/17331187/xml-dig-sig-error-after-upgrade-to-java7u25
    fixIDs(document.getDocumentElement());

    NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0) {
      throw new SignatureNotFoundException("Invalid SAML v2.0 operation. The signature is missing from the XML but is required.");
    }

    for (int i = 0; i < nl.getLength(); i++) {
      DOMValidateContext validateContext = new DOMValidateContext(keySelector, nl.item(i));
      XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
      try {
        XMLSignature signature = factory.unmarshalXMLSignature(validateContext);
        boolean valid = signature.validate(validateContext);
        if (!valid) {
          throw new SAMLException("Invalid SAML v2.0 operation. The signature is invalid.");
        }
      } catch (MarshalException e) {
        throw new SAMLException("Unable to verify XML signature in the SAML v2.0 XML. We couldn't unmarshall the XML Signature element.", e);
      } catch (XMLSignatureException e) {
        throw new SAMLException("Unable to verify XML signature in the SAML v2.0 XML. The signature was unmarshalled but we couldn't validate it. Possible reasons include a key was not provided that was eligible to verify the signature, or an un-expected exception occurred.", e);
      }
    }
  }

  private static class AuthnRequestParseResult {
    public AuthnRequestType authnRequest;

    public Document document;

    public AuthenticationRequest request;
  }
}
