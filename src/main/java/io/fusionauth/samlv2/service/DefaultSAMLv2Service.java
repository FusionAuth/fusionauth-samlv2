/*
 * Copyright (c) 2013-2024, Inversoft Inc., All Rights Reserved
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
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
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.TransformerException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.der.Tag;
import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.Binding;
import io.fusionauth.samlv2.domain.Conditions;
import io.fusionauth.samlv2.domain.ConfirmationMethod;
import io.fusionauth.samlv2.domain.DigestAlgorithm;
import io.fusionauth.samlv2.domain.EncryptionAlgorithm;
import io.fusionauth.samlv2.domain.KeyLocation;
import io.fusionauth.samlv2.domain.KeyTransportAlgorithm;
import io.fusionauth.samlv2.domain.LogoutRequest;
import io.fusionauth.samlv2.domain.LogoutResponse;
import io.fusionauth.samlv2.domain.MaskGenerationFunction;
import io.fusionauth.samlv2.domain.MetaData;
import io.fusionauth.samlv2.domain.MetaData.IDPMetaData;
import io.fusionauth.samlv2.domain.MetaData.SPMetaData;
import io.fusionauth.samlv2.domain.NameID;
import io.fusionauth.samlv2.domain.NameIDFormat;
import io.fusionauth.samlv2.domain.ResponseStatus;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.SAMLRequest;
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
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.LogoutRequestType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.NameIDPolicyType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.ObjectFactory;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.ResponseType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.StatusCodeType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.StatusResponseType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.StatusType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.DigestMethodType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.KeyInfoType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.X509DataType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc.CipherDataType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc.EncryptedDataType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc.EncryptedKeyType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc.EncryptionMethodType;
import io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc11.MGFType;
import io.fusionauth.samlv2.util.SAMLRequestParameters;
import io.fusionauth.samlv2.util.SAMLTools;
import jakarta.xml.bind.JAXBElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import static io.fusionauth.samlv2.util.SAMLTools.convertToZonedDateTime;
import static io.fusionauth.samlv2.util.SAMLTools.decodeAndInflate;
import static io.fusionauth.samlv2.util.SAMLTools.marshallToBytes;
import static io.fusionauth.samlv2.util.SAMLTools.marshallToDocument;
import static io.fusionauth.samlv2.util.SAMLTools.marshallToString;
import static io.fusionauth.samlv2.util.SAMLTools.newDocumentFromBytes;
import static io.fusionauth.samlv2.util.SAMLTools.parseNameId;
import static io.fusionauth.samlv2.util.SAMLTools.toXMLGregorianCalendar;
import static io.fusionauth.samlv2.util.SAMLTools.toZonedDateTime;
import static io.fusionauth.samlv2.util.SAMLTools.unmarshallFromDocument;

/**
 * Default implementation of the SAML service.
 *
 * @author Brian Pontarelli
 */
@SuppressWarnings("scwbasic-protection-set_CryptoSignatureApprovedHashingAlgorithm")
public class DefaultSAMLv2Service implements SAMLv2Service {
  static final ObjectFactory PROTOCOL_OBJECT_FACTORY = new ObjectFactory();

  private static final io.fusionauth.samlv2.domain.jaxb.oasis.assertion.ObjectFactory ASSERTION_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.oasis.assertion.ObjectFactory();

  private static final io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.ObjectFactory DSIG_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.ObjectFactory();

  private static final io.fusionauth.samlv2.domain.jaxb.oasis.metadata.ObjectFactory METADATA_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.oasis.metadata.ObjectFactory();

  private static final io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc11.ObjectFactory XENC11_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc11.ObjectFactory();

  private static final io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc.ObjectFactory XENC_OBJECT_FACTORY = new io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc.ObjectFactory();

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
                                   SignatureLocation signatureOption, boolean includeKeyInfo) throws SAMLException {
    return buildAuthnResponse(response, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod, signatureOption, includeKeyInfo,
        false, null, null, null, null, null, null);
  }

  @Override
  public String buildAuthnResponse(AuthenticationResponse response, boolean sign, PrivateKey privateKey,
                                   X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod,
                                   SignatureLocation signatureOption, boolean includeKeyInfo, boolean encrypt,
                                   EncryptionAlgorithm encryptionAlgorithm, KeyLocation keyLocation,
                                   KeyTransportAlgorithm transportAlgorithm, X509Certificate encryptionCertificate,
                                   DigestAlgorithm digest, MaskGenerationFunction mgf) throws SAMLException {
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
      String id = "_" + UUID.randomUUID();
      assertionType.setID(id);
      assertionType.setIssuer(jaxbResponse.getIssuer());
      assertionType.setIssueInstant(toXMLGregorianCalendar(now));
      assertionType.setVersion(response.version);

      // Subject (element)
      if (response.assertion.subject != null) {
        SubjectType subjectType = new SubjectType();

        // NameId (element)
        if (response.assertion.subject.nameIDs != null) {
          for (NameID nameId : response.assertion.subject.nameIDs) {
            NameIDType nameIdType = new NameIDType();
            nameIdType.setValue(nameId.id);
            nameIdType.setFormat(nameId.format);
            subjectType.getContent().add(ASSERTION_OBJECT_FACTORY.createNameID(nameIdType));
          }
        }

        // Subject confirmation (element)
        if (response.assertion.subject.subjectConfirmation != null) {
          SubjectConfirmationDataType dataType = new SubjectConfirmationDataType();
          dataType.setInResponseTo(response.assertion.subject.subjectConfirmation.inResponseTo);
          // SAML Profiles 4.1.4.2 <Response> Usage
          // - Subject Confirmation MUST NOT contain NotBefore.
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
        if (!response.assertion.conditions.audiences.isEmpty()) {
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

    // Sign the Assertion if requested
    if (sign && response.status.code == ResponseStatus.Success && signatureOption == SignatureLocation.Assertion) {
      try {
        Element toSign = (Element) document.getElementsByTagName("Assertion").item(0);
        // The 'Signature' must come directly after the 'Issuer' element.
        // Issuer is the only required element. See schema for AssertionType in section 2.3.3 of SAML Core.
        // - The next sibling of the 'Issuer' may be null, this will cause the Signature to be inserted as the last element
        //   of the assertion which is what we want.
        Node issuer = toSign.getElementsByTagName("Issuer").item(0);
        Node insertBefore = issuer.getNextSibling();

        signXML(privateKey, certificate, algorithm, xmlSignatureC14nMethod, toSign, insertBefore, includeKeyInfo);
      } catch (Exception e) {
        throw new SAMLException("Unable to sign XML SAML assertion", e);
      }
    }

    if (encrypt && response.status.code == ResponseStatus.Success) {
      // Encrypt the <Assertion> element in the document and generate a new document with the <EncryptedAssertion> in its place
      document = encryptAssertion(document, encryptionAlgorithm, keyLocation, transportAlgorithm, encryptionCertificate, digest, mgf);
    }

    // Sign the response if requested or if the response is a failure (successes may have had the assertion signed above)
    if (sign && (signatureOption == SignatureLocation.Response || response.status.code != ResponseStatus.Success)) {
      try {
        Element toSign = document.getDocumentElement();
        // The only required element in the StatusResponseType is Status. See Section 3.2.2 in SAML Core.
        // The children will be a sequence that must exist in the order of 'Issuer', 'Signature', 'Extensions', and then 'Status'
        // - If the first element is 'Issuer', then the next sibling will be used for 'insertBefore'.
        // - If the first element is NOT 'Issuer', it MUST be 'Extensions' or 'Status', and thus is the 'insertBefore' node.
        Node insertBefore = findSignatureInsertLocation(toSign);
        signXML(privateKey, certificate, algorithm, xmlSignatureC14nMethod, toSign, insertBefore, includeKeyInfo);
      } catch (Exception e) {
        throw new SAMLException("Unable to sign XML SAML response", e);
      }
    }

    // Marshall the XML to a string and base64 encode the response
    try {
      String xml = marshallToString(document);
      return new String(Base64.getEncoder().encode(xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    } catch (TransformerException e) {
      throw new SAMLException("Unable to marshall the SAML response to XML.", e);
    }
  }

  @Override
  public String buildMetadataResponse(MetaData metaData) throws SAMLException {
    EntityDescriptorType root = new EntityDescriptorType();
    root.setID("_" + metaData.id);
    root.setEntityID(metaData.entityId);

    if (metaData.idp != null) {
      IDPSSODescriptorType idp = new IDPSSODescriptorType();
      idp.getProtocolSupportEnumeration().add("urn:oasis:names:tc:SAML:2.0:protocol");
      idp.setWantAuthnRequestsSigned(metaData.idp.wantAuthnRequestsSigned);

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
    return buildPostRequest(PROTOCOL_OBJECT_FACTORY.createAuthnRequest(authnRequest), AuthnRequestType.class, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod, true);
  }

  @Override
  public String buildPostLogoutRequest(LogoutRequest request, boolean sign, PrivateKey privateKey,
                                       X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod)
      throws SAMLException {
    LogoutRequestType logoutRequest = toLogoutRequest(request, "2.0");
    return buildPostRequest(PROTOCOL_OBJECT_FACTORY.createLogoutRequest(logoutRequest), LogoutRequestType.class, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod, true);

  }

  @Override
  public String buildPostLogoutResponse(LogoutResponse response, boolean sign, PrivateKey privateKey,
                                        X509Certificate certificate, Algorithm algorithm, String xmlSignatureC14nMethod)
      throws SAMLException {
    StatusResponseType logoutResponse = toLogoutResponse(response, "2.0");
    return buildPostRequest(PROTOCOL_OBJECT_FACTORY.createLogoutResponse(logoutResponse), StatusResponseType.class, sign, privateKey, certificate, algorithm, xmlSignatureC14nMethod, true);
  }

  @Override
  public String buildRedirectAuthnRequest(AuthenticationRequest request, String relayState, boolean sign,
                                          PrivateKey key, Algorithm algorithm) throws SAMLException {
    AuthnRequestType authnRequest = toAuthnRequest(request, "2.0");
    return buildRedirectRequest(PROTOCOL_OBJECT_FACTORY.createAuthnRequest(authnRequest), AuthnRequestType.class, relayState, sign, key, algorithm);
  }

  @Override
  public String buildRedirectLogoutRequest(LogoutRequest request, String relayState, boolean sign, PrivateKey key,
                                           Algorithm algorithm)
      throws SAMLException {
    LogoutRequestType logoutRequest = toLogoutRequest(request, "2.0");
    return buildRedirectRequest(PROTOCOL_OBJECT_FACTORY.createLogoutRequest(logoutRequest), LogoutRequestType.class, relayState, sign, key, algorithm);
  }

  @Override
  public String buildRedirectLogoutResponse(LogoutResponse response, String relayState, boolean sign, PrivateKey key,
                                            Algorithm algorithm) throws SAMLException {
    StatusResponseType logoutResponse = toLogoutResponse(response, "2.0");
    return buildRedirectResponse(PROTOCOL_OBJECT_FACTORY.createLogoutResponse(logoutResponse), StatusResponseType.class, relayState, sign, key, algorithm);
  }

  @Override
  public LogoutRequest parseLogoutRequestPostBinding(String encodedRequest,
                                                     Function<LogoutRequest, PostBindingSignatureHelper> signatureHelperFunction)
      throws SAMLException {
    byte[] xml = Base64.getMimeDecoder().decode(encodedRequest);
    LogoutRequestParseResult result = parseLogoutRequest(xml);
    PostBindingSignatureHelper signatureHelper = signatureHelperFunction.apply(result.request);
    if (signatureHelper.verifySignature()) {
      verifyEmbeddedSignature(result.document, signatureHelper.keySelector(), result.request);
    }

    return result.request;
  }

  @Override
  public LogoutRequest parseLogoutRequestRedirectBinding(String queryString,
                                                         Function<LogoutRequest, RedirectBindingSignatureHelper> signatureHelperFunction)
      throws SAMLException {
    SAMLRequestParameters requestParameters = SAMLTools.parseQueryString(queryString);
    LogoutRequestParseResult result = parseLogoutRequest(decodeAndInflate(requestParameters.urlDecodedSAMLRequest()));
    RedirectBindingSignatureHelper signatureHelper = signatureHelperFunction.apply(result.request);
    if (signatureHelper.verifySignature()) {
      verifyRequestSignature(requestParameters, signatureHelper, result.request);
    }

    return result.request;
  }

  @Override
  public LogoutResponse parseLogoutResponsePostBinding(String encodedRequest,
                                                       Function<LogoutResponse, PostBindingSignatureHelper> signatureHelperFunction)
      throws SAMLException {
    byte[] xml = Base64.getMimeDecoder().decode(encodedRequest);
    LogoutResponseParseResult result = parseLogoutResponse(xml);
    PostBindingSignatureHelper signatureHelper = signatureHelperFunction.apply(result.response);
    if (signatureHelper.verifySignature()) {
      verifyEmbeddedSignature(result.document, signatureHelper.keySelector(), result.response);
    }

    return result.response;
  }

  @Override
  public LogoutResponse parseLogoutResponseRedirectBinding(String queryString,
                                                           Function<LogoutResponse, RedirectBindingSignatureHelper> signatureHelperFunction)
      throws SAMLException {
    SAMLRequestParameters requestParameters = SAMLTools.parseQueryString(queryString);
    LogoutResponseParseResult result = parseLogoutResponse(decodeAndInflate(requestParameters.urlDecodedSAMLRequest()));
    RedirectBindingSignatureHelper signatureHelper = signatureHelperFunction.apply(result.response);
    if (signatureHelper.verifySignature()) {
      verifyRequestSignature(requestParameters, signatureHelper, result.response);
    }

    return result.response;
  }

  @Override
  public MetaData parseMetaData(String metaDataXML) throws SAMLException {
    Document document = newDocumentFromBytes(metaDataXML.getBytes(StandardCharsets.UTF_8));
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
                                       .map(SAMLTools::toCertificate)
                                       .filter(Objects::nonNull)
                                       .collect(Collectors.toList());
      } catch (IllegalArgumentException e) {
        // toPublicKey might throw an exception, we want to translate it back to a known exception
        throw new SAMLException(e.getCause());
      }
    }

    Optional<RoleDescriptorType> spDescriptor = roles.stream()
                                                     .filter(r -> r instanceof SPSSODescriptorType)
                                                     .findFirst();

    if (spDescriptor.isPresent()) {
      SPSSODescriptorType sp = (SPSSODescriptorType) spDescriptor.get();
      metaData.sp = new SPMetaData();
      metaData.sp.acsEndpoint = !sp.getAssertionConsumerService().isEmpty() ? sp.getAssertionConsumerService().get(0).getLocation() : null;
      try {
        metaData.sp.nameIDFormat = !sp.getNameIDFormat().isEmpty() ? NameIDFormat.fromSAMLFormat(sp.getNameIDFormat().get(0)) : null;
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
      verifyEmbeddedSignature(result.document, signatureHelper.keySelector(), result.request);
    }

    return result.request;
  }

  @Override
  public AuthenticationRequest parseRequestRedirectBinding(String queryString,
                                                           Function<AuthenticationRequest, RedirectBindingSignatureHelper> signatureHelperFunction)
      throws SAMLException {
    SAMLRequestParameters requestParameters = SAMLTools.parseQueryString(queryString);
    AuthnRequestParseResult result = parseRequest(decodeAndInflate(requestParameters.urlDecodedSAMLRequest()));
    RedirectBindingSignatureHelper signatureHelper = signatureHelperFunction.apply(result.request);
    if (signatureHelper.verifySignature()) {
      verifyRequestSignature(requestParameters, signatureHelper, result.request);
    }

    return result.request;
  }

  @Override
  public AuthenticationResponse parseResponse(String encodedResponse, boolean verifySignature, KeySelector keySelector)
      throws SAMLException {
    return parseResponse(encodedResponse, verifySignature, keySelector, false, null);
  }

  @Override
  public AuthenticationResponse parseResponse(String encodedResponse, boolean verifySignature,
                                              KeySelector signatureKeySelector, boolean requireEncryptedAssertion,
                                              PrivateKey encryptionKey)
      throws SAMLException {

    AuthenticationResponse response = new AuthenticationResponse();
    byte[] decodedResponse = Base64.getMimeDecoder().decode(encodedResponse);
    response.rawResponse = new String(decodedResponse, StandardCharsets.UTF_8);

    Document document = newDocumentFromBytes(decodedResponse);
    if (verifySignature) {
      verifyEmbeddedSignature(document, signatureKeySelector, null);
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
        if (encryptionKey == null) {
          logger.warn("SAML response contained encrypted attribute, but no encryption key was provided. It was ignored.");
          continue;
        } else {
          assertion = decryptAssertion((EncryptedElementType) assertion, encryptionKey);
        }
      } else if (requireEncryptedAssertion) {
        logger.warn("Assertion encryption is required, but the SAML response contained an unencrypted attribute. It was ignored.");
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
            if (response.assertion.subject.nameIDs == null) {
              response.assertion.subject.nameIDs = new ArrayList<>();
            }

            // Extract the name
            response.assertion.subject.nameIDs.add(parseNameId((NameIDType) element.getValue()));
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
          if (conditionAbstractType instanceof AudienceRestrictionType restrictionType) {
            response.assertion.conditions.audiences.addAll(restrictionType.getAudience());
          }
        }
      }

      // Handle the attributes
      List<StatementAbstractType> statements = assertionType.getStatementOrAuthnStatementOrAuthzDecisionStatement();
      for (StatementAbstractType statement : statements) {
        if (statement instanceof AttributeStatementType attributeStatementType) {
          List<Object> attributeObjects = attributeStatementType.getAttributeOrEncryptedAttribute();
          for (Object attributeObject : attributeObjects) {
            if (attributeObject instanceof AttributeType attributeType) {
              String name = attributeType.getName();
              List<Object> attributeValues = attributeType.getAttributeValue();
              List<String> values = attributeValues.stream().map(SAMLTools::attributeToString).toList();
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

  protected String urlEncode(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }

  @SuppressWarnings("SameParameterValue")
  <T> String buildPostRequest(JAXBElement<T> object, Class<T> type, boolean sign, PrivateKey privateKey,
                              X509Certificate certificate,
                              Algorithm algorithm, String xmlSignatureC14nMethod, boolean includeKeyInfo)
      throws SAMLException {
    Document document = marshallToDocument(object, type);

    // Sign the request if requested
    if (sign) {
      try {
        Element toSign = document.getDocumentElement();
        // This method is used for AuthnRequestType, LogoutRequestType, and StatusResponseType (LogoutResponse)
        // The only required element in the StatusResponseType is Status. See Section 3.2.2 in SAML Core.
        // The children will be a sequence that must exist in the order of 'Issuer', 'Signature', 'Extensions', and then 'Status'
        // - If the first element is 'Issuer', then the next sibling will be used for 'insertBefore'.
        // - If the first element is NOT 'Issuer', it MUST be 'Extensions' or 'Status', and thus is the 'insertBefore' node.
        //
        // AuthnRequestType and LogoutRequestType both extend RequestAbstractType.
        //  - AuthnRequestType has no required fields. See Section 3.4.1 in SAML Core.
        //  - LogoutRequestType only requires an ID field. See Section 3.7.1 in SAML Core.
        // The RequestAbstractType requires its children in the sequence of 'Issuer', 'Signature', and then 'Extensions'. See Section 3.2.1 in SAML Core.
        // - If the first element is 'Issuer', then the next sibling will be used for 'insertBefore'.
        // - If the first element is NOT 'Issuer', it MUST be 'Extensions', and thus is the 'insertBefore' node.
        Node insertBefore = findSignatureInsertLocation(toSign);
        signXML(privateKey, certificate, algorithm, xmlSignatureC14nMethod, toSign, insertBefore, includeKeyInfo);
      } catch (Exception e) {
        throw new SAMLException("Unable to sign XML SAML request", e);
      }
    }

    try {
      String xml = marshallToString(document);
      return new String(Base64.getEncoder().encode(xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new SAMLException("Unable to marshall the SAML request to XML", e);
    }
  }

  <T> String buildRedirect(JAXBElement<T> object, Class<T> type, String relayState, boolean sign,
                           PrivateKey key, Algorithm algorithm, String parameterName) throws SAMLException {
    try {
      byte[] xml = marshallToBytes(object, type);
      String encodedResult = SAMLTools.deflateAndEncode(xml);
      String parameters = parameterName + "=" + urlEncode(encodedResult);
      if (relayState != null) {
        parameters += "&RelayState=" + urlEncode(relayState);
      }

      if (sign && key != null && algorithm != null) {
        Signature signature;
        parameters += "&SigAlg=" + urlEncode(algorithm.uri);
        signature = Signature.getInstance(algorithm.name);
        signature.initSign(key);
        signature.update(parameters.getBytes(StandardCharsets.UTF_8));

        String signatureParameter = new String(Base64.getEncoder().encode(signature.sign()), StandardCharsets.UTF_8);
        parameters += "&Signature=" + urlEncode(signatureParameter);
      }

      return parameters;
    } catch (Exception e) {
      // Not possible but freak out
      throw new SAMLException(e);
    }
  }

  <T> String buildRedirectRequest(JAXBElement<T> object, Class<T> type, String relayState, boolean sign,
                                  PrivateKey key, Algorithm algorithm) throws SAMLException {
    return buildRedirect(object, type, relayState, sign, key, algorithm, "SAMLRequest");
  }

  @SuppressWarnings("SameParameterValue")
  <T> String buildRedirectResponse(JAXBElement<T> object, Class<T> type, String relayState, boolean sign,
                                   PrivateKey key, Algorithm algorithm) throws SAMLException {
    return buildRedirect(object, type, relayState, sign, key, algorithm, "SAMLResponse");
  }

  AuthnRequestType toAuthnRequest(AuthenticationRequest request, String version) throws SAMLException {
    // SAML Web SSO profile requirements (section 4.1.4.1)
    AuthnRequestType authnRequest = new AuthnRequestType();
    authnRequest.setAssertionConsumerServiceURL(request.acsURL);
    authnRequest.setDestination(request.destination);
    authnRequest.setIssuer(new NameIDType());
    authnRequest.getIssuer().setValue(request.issuer);
    authnRequest.setNameIDPolicy(new NameIDPolicyType());
    // Default to EmailAddress for backwards compatibility
    authnRequest.getNameIDPolicy().setFormat(request.nameIdFormat != null ? request.nameIdFormat : NameIDFormat.EmailAddress.toSAMLFormat());
    if (request.allowCreate != null) {
      authnRequest.getNameIDPolicy().setAllowCreate(request.allowCreate);
    }
    authnRequest.setID(request.id);
    authnRequest.setVersion(version);
    authnRequest.setIssueInstant(SAMLTools.toXMLGregorianCalendar(ZonedDateTime.now(ZoneOffset.UTC)));
    return authnRequest;
  }

  LogoutRequestType toLogoutRequest(LogoutRequest request, String version) throws SAMLException {
    LogoutRequestType logoutRequest = new LogoutRequestType();
    logoutRequest.setDestination(request.destination);
    logoutRequest.setIssuer(new NameIDType());
    logoutRequest.getIssuer().setValue(request.issuer);
    logoutRequest.setNameID(new NameIDType());
    logoutRequest.getNameID().setFormat(NameIDFormat.EmailAddress.toSAMLFormat());
    logoutRequest.setID(request.id);
    logoutRequest.getSessionIndex().add(request.sessionIndex);
    logoutRequest.setVersion(version);
    logoutRequest.setIssueInstant(SAMLTools.toXMLGregorianCalendar(ZonedDateTime.now(ZoneOffset.UTC)));
    return logoutRequest;
  }

  @SuppressWarnings("SameParameterValue")
  StatusResponseType toLogoutResponse(LogoutResponse response, String version) throws SAMLException {
    StatusResponseType logoutResponse = new StatusResponseType();
    logoutResponse.setDestination(response.destination);
    logoutResponse.setIssuer(new NameIDType());
    logoutResponse.getIssuer().setValue(response.issuer);
    logoutResponse.setID(response.id);
    logoutResponse.setVersion(version);
    logoutResponse.setInResponseTo(response.inResponseTo);
    logoutResponse.setIssueInstant(SAMLTools.toXMLGregorianCalendar(ZonedDateTime.now(ZoneOffset.UTC)));
    StatusType status = new StatusType();
    status.setStatusCode(new StatusCodeType());
    status.getStatusCode().setValue(response.status.code.toSAMLFormat());
    status.setStatusMessage(response.status.message);
    logoutResponse.setStatus(status);
    return logoutResponse;
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

  /**
   * Build the {@code EncryptedAssertion} XML element as defined by the <a
   * href="https://www.w3.org/TR/xmlenc-core1/">XML Encryption spec</a>
   *
   * @param encryptionAlgorithm The algorithm used to encrypt the assertion
   * @param assertionValue      The encrypted assertion as a byte array
   * @param encryptedKeyElement The wrapped encrypted key JAXB XML element
   * @param keyLocation         The location in the {@code EncryptedAssertion} where the {@code EncryptedKey} should be
   *                            placed
   * @return A JAXB XML element for the SAML {@code EncryptedAssertion}
   */
  private EncryptedElementType buildEncryptedAssertion(EncryptionAlgorithm encryptionAlgorithm, byte[] assertionValue,
                                                       EncryptedKeyType encryptedKeyElement, KeyLocation keyLocation) {
    // Create the EncryptedData element
    EncryptedDataType encryptedData = new EncryptedDataType();
    encryptedData.setType("http://www.w3.org/2001/04/xmlenc#Element");

    // Set the EncryptionMethod for the SAML assertion and add to EncryptedData
    EncryptionMethodType encryptionMethod = new EncryptionMethodType();
    encryptionMethod.setAlgorithm(encryptionAlgorithm.uri);
    encryptedData.setEncryptionMethod(encryptionMethod);

    // Create the CipherData and add to EncryptedData
    CipherDataType cipherData = new CipherDataType();
    cipherData.setCipherValue(assertionValue);
    encryptedData.setCipherData(cipherData);

    // Create the EncryptedAssertion and add EncryptedData element
    EncryptedElementType encryptedAssertion = new EncryptedElementType();
    encryptedAssertion.setEncryptedData(encryptedData);

    if (keyLocation == KeyLocation.Child) {
      // The EncryptedKey should be wrapped in ds:KeyInfo and added as a child of EncryptedData
      KeyInfoType keyInfo = new KeyInfoType();
      // The EncryptedKey element needs to be wrapped in a JAXBElement in order to be marshalled to an XML Document
      keyInfo.getContent().add(XENC_OBJECT_FACTORY.createEncryptedKey(encryptedKeyElement));
      encryptedData.setKeyInfo(keyInfo);
    } else {
      // The EncryptedKey should be a sibling of EncryptedData
      encryptedAssertion.getEncryptedKey().add(encryptedKeyElement);
    }

    return encryptedAssertion;
  }

  /**
   * Wrap the encrypted key value in an {@code EncryptedKey} XML element as defined by the <a
   * href="https://www.w3.org/TR/xmlenc-core1/">XML Encryption spec</a>
   *
   * @param encryptedKeyValue  The encrypted key value as a byte array
   * @param transportAlgorithm The algorithm used to encrypt the key
   * @param digest             The message digest algorithm for RSA-OAEP (if necessary)
   * @param mgf                The Mask Generation function for RSA-OAEP (if necessary)
   * @return The {@code EncryptedKey} JAXB XML element
   */
  private EncryptedKeyType buildEncryptedKey(byte[] encryptedKeyValue, KeyTransportAlgorithm transportAlgorithm,
                                             DigestAlgorithm digest, MaskGenerationFunction mgf) throws SAMLException {
    // Create EncryptionMethod element
    EncryptionMethodType encryptionMethod = new EncryptionMethodType();
    encryptionMethod.setAlgorithm(transportAlgorithm.uri);

    if (transportAlgorithm != KeyTransportAlgorithm.RSAv15) {
      // Add DigestMethod for OAEP
      DigestMethodType digestMethod = new DigestMethodType();
      digestMethod.setAlgorithm(digest.uri);
      // We need to add DigestMethod as an Element in order to marshall the full response later
      // We may be able to avoid this by regenerating the JAXB objects all at once, so they know about each other
      Document doc = marshallToDocument(DSIG_OBJECT_FACTORY.createDigestMethod(digestMethod), DigestMethodType.class);
      encryptionMethod.getContent().add(doc.getDocumentElement());

      if (transportAlgorithm == KeyTransportAlgorithm.RSA_OAEP) {
        // Add MGF algorithm
        MGFType mgfType = new MGFType();
        mgfType.setAlgorithm(mgf.uri);
        // We need to add MGF as an Element in order to marshall the full response later
        // We may be able to avoid this by regenerating the JAXB objects all at once, so they know about each other
        // Exception is: jakarta.xml.bind.JAXBException: io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc11.MGFType is not known to this context
        Document mgfDoc = marshallToDocument(XENC11_OBJECT_FACTORY.createMGF(mgfType), MGFType.class);
        encryptionMethod.getContent().add(mgfDoc.getDocumentElement());
      }
    }

    // Create CipherData element
    CipherDataType cipherData = new CipherDataType();
    cipherData.setCipherValue(encryptedKeyValue);

    // Create top-level EncryptedKey element
    EncryptedKeyType encryptedKey = new EncryptedKeyType();
    encryptedKey.setEncryptionMethod(encryptionMethod);
    encryptedKey.setCipherData(cipherData);

    return encryptedKey;
  }

  private void checkFor_CVE_2022_21449(SAMLRequest request, byte[] signature) throws SAMLException {
    if (signature.length == 0) {
      return;
    }

    byte[] r;
    byte[] s;

    // Assume if the first byte is 48 (sequence) and the second byte is a positive integer that matches the actual length,
    // this is likely DER encoded. If it is not a sequence, it is likely a raw signature, which is just r + s.
    if (signature[0] == Tag.Sequence && signature[1] == signature.length - 2) {
      try {
        DerValue[] sequence = new DerInputStream(signature).getSequence();
        if (sequence.length != 2) {
          return;
        }

        r = sequence[0].toByteArray();
        s = sequence[1].toByteArray();
      } catch (Exception e) {
        throw new SAMLException("Invalid SAML v2.0 operation. The signature is invalid.", request, e);
      }
    } else {
      int half = signature.length / 2;
      r = Arrays.copyOfRange(signature, 0, half);
      s = Arrays.copyOfRange(signature, half, signature.length);
    }

    boolean rOk = false;
    boolean sOk = false;

    // Ensure r is not 0
    for (byte b : r) {
      rOk = b != 0;
      if (rOk) {
        break;
      }
    }

    // Ensure s is not 0
    for (byte b : s) {
      sOk = b != 0;
      if (sOk) {
        break;
      }
    }

    if (!rOk || !sOk) {
      throw new SAMLException("Invalid SAML v2.0 operation. The signature is invalid.", request);
    }
  }

  /**
   * Creates the algorithm parameter spec according to the selected encryption algorithm
   *
   * @param encryptionAlgorithm The encryption algorithm
   * @param iv                  The initialization vector
   * @return The algorithm parameter spec for initializing the {@link Cipher}
   */
  private AlgorithmParameterSpec createAlgorithmParameterSpec(EncryptionAlgorithm encryptionAlgorithm, byte[] iv) {
    if (List.of(EncryptionAlgorithm.AES128GCM, EncryptionAlgorithm.AES192GCM, EncryptionAlgorithm.AES256GCM).contains(encryptionAlgorithm)) {
      return new GCMParameterSpec(128, iv);
    } else {
      return new IvParameterSpec(iv);
    }
  }

  /**
   * Decrypt an encrypted XML element according to the XML Encryption spec
   *
   * @param encryptedAssertion     an {@code EncryptedElement} containing an encrypted assertion
   * @param transportEncryptionKey a private key used to decrypt the symmetric key used to decrypt the assertion
   * @return the decrypted {@code Assertion} element
   * @throws SAMLException if there was an issue decrypting the {@code EncryptedElement} to a SAML {@code Assertion}
   *                       element
   */
  private AssertionType decryptAssertion(EncryptedElementType encryptedAssertion, PrivateKey transportEncryptionKey)
      throws SAMLException {
    // Extract the encrypted assertion encryption key from the XML
    EncryptedKeyType encryptedKey = extractEncryptedAssertionEncryptionKey(encryptedAssertion);

    // Determine the assertion EncryptionAlgorithm.
    var assertionEncryptionAlgorithmUri = encryptedAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm();
    var assertionEncryptionAlgorithm = EncryptionAlgorithm.fromURI(assertionEncryptionAlgorithmUri);
    if (assertionEncryptionAlgorithm == null) {
      throw new SAMLException("Unable to determine assertion encryption algorithm from URI [" + assertionEncryptionAlgorithmUri + "]");
    }

    // Decrypt the assertion encryption key using the transport key
    Key assertionEncryptionKey;
    try {
      assertionEncryptionKey = decryptKey(encryptedKey, transportEncryptionKey, assertionEncryptionAlgorithm);
    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
             InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
      throw new SAMLException("Unable to decrypt symmetric key using transport key", e);
    }

    // Decrypt the assertion using the decrypted symmetric key
    byte[] assertionBytes;
    try {
      assertionBytes = decryptElement(encryptedAssertion.getEncryptedData().getCipherData().getCipherValue(), assertionEncryptionAlgorithm, assertionEncryptionKey);
    } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
             InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
      throw new SAMLException("Unable to decrypt assertion using symmetric key", e);
    }

    // Parse the bytes into an XML document and then unmarshall into the AssertionType
    Document doc = newDocumentFromBytes(assertionBytes);
    return unmarshallFromDocument(doc, AssertionType.class);
  }

  /**
   * Decrypt the provided bytes and return the result
   *
   * @param encryptedAssertionBytes      the ciphertext for the encrypted assertion
   * @param assertionEncryptionAlgorithm the algorithm used to encrypt the assertion
   * @param assertionEncryptionKey       a symmetric key used to decrypt the assertion
   * @return the plaintext element XML
   */
  private byte[] decryptElement(byte[] encryptedAssertionBytes, EncryptionAlgorithm assertionEncryptionAlgorithm,
                                Key assertionEncryptionKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    byte[] iv = Arrays.copyOfRange(encryptedAssertionBytes, 0, assertionEncryptionAlgorithm.ivLength);
    byte[] cipherValue = Arrays.copyOfRange(encryptedAssertionBytes, assertionEncryptionAlgorithm.ivLength, encryptedAssertionBytes.length);
    // Initialize the cipher
    AlgorithmParameterSpec spec = createAlgorithmParameterSpec(assertionEncryptionAlgorithm, iv);
    Cipher cipher = Cipher.getInstance(assertionEncryptionAlgorithm.transformation);
    cipher.init(Cipher.DECRYPT_MODE, assertionEncryptionKey, spec);
    return cipher.doFinal(cipherValue);
  }

  /**
   * Decrypts the provided {@code EncryptedKey} element and creates a symmetric encryption key from the value
   *
   * @param encryptedKey                 the {@code EncryptedKey} element
   * @param transportEncryptionKey       the private key used to decrypt the symmetric key
   * @param assertionEncryptionAlgorithm the algorithm used to encrypt/decrypt the assertion
   * @return the decrypted symmetric key
   * @throws SAMLException if there was an issue extracting an encryption parameter from the {@code EncryptedKey} XML
   */
  private Key decryptKey(EncryptedKeyType encryptedKey, PrivateKey transportEncryptionKey,
                         EncryptionAlgorithm assertionEncryptionAlgorithm)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, SAMLException {
    EncryptionMethodType encryptionMethod = encryptedKey.getEncryptionMethod();
    String transportAlgorithmUri = encryptionMethod.getAlgorithm();
    KeyTransportAlgorithm transportAlgorithm = KeyTransportAlgorithm.fromURI(transportAlgorithmUri);
    if (transportAlgorithm == null) {
      throw new SAMLException("Unable to determine key transport encryption algorithm from URI [" + transportAlgorithmUri + "]");
    }
    // Create the cipher instance
    Cipher cipher = Cipher.getInstance(transportAlgorithm.transformation);

    if (transportAlgorithm == KeyTransportAlgorithm.RSAv15) {
      cipher.init(Cipher.DECRYPT_MODE, transportEncryptionKey);
    } else {
      // Extract URIs for OAEP parameters
      String digestUri = null;
      String mgfUri = null;

      for (Object item : encryptionMethod.getContent()) {
        // The DigestMethod is parsed as a JAXB element while MGF is parsed as a W3C DOM Element.
        // Cover both cases for determining other parameters
        if (item instanceof JAXBElement<?>) {
          JAXBElement<?> element = (JAXBElement<?>) item;
          if (element.getDeclaredType() == DigestMethodType.class) {
            DigestMethodType digestMethod = (DigestMethodType) element.getValue();
            digestUri = digestMethod.getAlgorithm();
          } else if (element.getDeclaredType() == MGFType.class) {
            MGFType mgfType = (MGFType) element.getValue();
            mgfUri = mgfType.getAlgorithm();
          }
        } else if (item instanceof Element) {
          Element element = (Element) item;
          if (element.getTagName().equals("DigestMethod")) {
            digestUri = element.getAttribute("Algorithm");
          } else if (element.getTagName().equals("MGF")) {
            mgfUri = element.getAttribute("Algorithm");
          }
        }
      }

      // Extract other parameters for OAEP
      DigestAlgorithm digest = DigestAlgorithm.fromURI(digestUri);
      MaskGenerationFunction mgf = MaskGenerationFunction.fromURI(mgfUri);

      if (transportAlgorithm == KeyTransportAlgorithm.RSA_OAEP_MGF1P) {
        // The RSA_OAEP_MGF1P implies the use of SHA-1 for the MGF digest algorithm
        mgf = MaskGenerationFunction.MGF1_SHA1;
      }

      if (digest == null) {
        throw new SAMLException("Unable to determine digest algorithm from URI [" + digestUri + "]");
      }
      if (mgf == null) {
        throw new SAMLException("Unable to determine mask generation function from URI [" + mgfUri + "]");
      }

      OAEPParameterSpec oaepParameters = new OAEPParameterSpec(
          digest.digest,
          "MGF1",
          new MGF1ParameterSpec(mgf.digest),
          // Use the default (empty byte[])
          PSpecified.DEFAULT
      );
      cipher.init(Cipher.DECRYPT_MODE, transportEncryptionKey, oaepParameters);
    }

    byte[] encryptedBytes = encryptedKey.getCipherData().getCipherValue();

    // Get the decrypted bytes for the key and return the result
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    if (assertionEncryptionAlgorithm == EncryptionAlgorithm.TripleDES) {
      return SecretKeyFactory.getInstance("DESede")
                             .generateSecret(new DESedeKeySpec(decryptedBytes));
    } else {
      return new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, "AES");
    }
  }

  /**
   * Encrypt the SAML Assertion in the XML document and return a new XML document with the Assertion replaced by
   * EncryptedAssertion
   *
   * @param document              The XML document containing the SAML Response with an unencrypted Assertion
   * @param encryptionAlgorithm   The algorithm used to encrypt the SAML Assertion
   * @param keyLocation           The location to place the EncryptedKey in EncryptedAssertion
   * @param transportAlgorithm    The algorithm used to encrypt the symmetric key for transport
   * @param encryptionCertificate The certificate containing the public key for encrypting the symmetric key
   * @param digest                The message digest algorithm to use with RSA-OAEP encryption (if necessary)
   * @param mgf                   The mask generation function to use with RSA-OAEP encryption (if necessary)
   * @return A new XML document containing the SAML response with an EncryptedAssertion
   * @throws SAMLException if there is an issue encrypting the SAML Assertion or generating a new document
   */
  private Document encryptAssertion(Document document, EncryptionAlgorithm encryptionAlgorithm, KeyLocation keyLocation,
                                    KeyTransportAlgorithm transportAlgorithm, X509Certificate encryptionCertificate,
                                    DigestAlgorithm digest, MaskGenerationFunction mgf) throws SAMLException {
    // Get the Assertion element to encrypt and marshall to XML string
    Element toEncrypt = (Element) document.getElementsByTagName("Assertion").item(0);
    String xmlToEncrypt;
    try {
      xmlToEncrypt = marshallToString(toEncrypt);
    } catch (TransformerException e) {
      throw new SAMLException("Unable to marshall the element to XML.", e);
    }

    // Generate symmetric key material for encrypting the assertion
    Key k;
    byte[] iv;
    try {
      k = generateAssertionEncryptionKey(encryptionAlgorithm);
      iv = generateIV(encryptionAlgorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new SAMLException("Unable to generate symmetric key encryption parameters for assertion encryption", e);
    }

    // Encrypt the Assertion element to a byte array
    byte[] assertionValue;
    try {
      assertionValue = encryptElement(xmlToEncrypt, encryptionAlgorithm, k, iv);
    } catch (Exception e) {
      throw new SAMLException("Unable to encrypt assertion using symmetric key", e);
    }

    // Encrypt the symmetric key to a byte array
    byte[] encryptedKeyValue;
    try {
      encryptedKeyValue = encryptKey(k, transportAlgorithm, encryptionCertificate, digest, mgf);
    } catch (Exception e) {
      throw new SAMLException("Unable to encrypt symmetric key for transport", e);
    }

    // Build the EncryptedKey element
    EncryptedKeyType encryptedKeyElement = buildEncryptedKey(encryptedKeyValue, transportAlgorithm, digest, mgf);

    // Build the EncryptedAssertion element
    EncryptedElementType encryptedAssertion = buildEncryptedAssertion(encryptionAlgorithm, assertionValue, encryptedKeyElement, keyLocation);

    // Unmarshall the XML document
    ResponseType samlResponse = unmarshallFromDocument(document, ResponseType.class);
    // Clear the unencrypted Assertion and add the EncryptedAssertion
    samlResponse.getAssertionOrEncryptedAssertion().clear();
    samlResponse.getAssertionOrEncryptedAssertion().add(encryptedAssertion);

    // Marshall the JAXB XML back to a document
    return marshallToDocument(PROTOCOL_OBJECT_FACTORY.createResponse(samlResponse), ResponseType.class);
  }

  /**
   * Encrypts the provided XML string using the provided symmetric key parameters and returns a byte array containing
   * the ciphertext
   *
   * @param xmlToEncrypt        The XML string to be encrypted
   * @param encryptionAlgorithm The algorithm to be used to encrypt the data
   * @param k                   The symmetric encryption key
   * @param iv                  The initialization vector for the encryption algorithm
   * @return A byte array containing the ciphertext
   */
  private byte[] encryptElement(String xmlToEncrypt, EncryptionAlgorithm encryptionAlgorithm, Key k, byte[] iv)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    // Initialize the cipher
    AlgorithmParameterSpec spec = createAlgorithmParameterSpec(encryptionAlgorithm, iv);
    Cipher cipher = Cipher.getInstance(encryptionAlgorithm.transformation);
    cipher.init(Cipher.ENCRYPT_MODE, k, spec);

    // Encrypt the XML string. AES-GCM ciphers will generate and append the Authentication Tag to resulting ciphertext
    byte[] ciphertext = cipher.doFinal(xmlToEncrypt.getBytes(StandardCharsets.UTF_8));
    // Concatenate the IV and ciphertext and return the result
    return ByteBuffer.allocate(iv.length + ciphertext.length)
                     .put(iv)
                     .put(ciphertext)
                     .array();
  }

  /**
   * Encrypt the symmetric key using the provided cipher information and return a byte array containing ciphertext
   *
   * @param key                   The symmetric key to encrypt
   * @param transportAlgorithm    The algorithm used to encrypt the symmetric key for transport
   * @param encryptionCertificate The certificate containing the RSA public key to use for encryption
   * @param digest                The message digest algorithm to use with RSA-OAEP encryption (if necessary)
   * @param mgf                   The mask generation function to use with RSA-OAEP encryption (if necessary)
   * @return A byte array containing the ciphertext
   */
  private byte[] encryptKey(Key key, KeyTransportAlgorithm transportAlgorithm, X509Certificate encryptionCertificate,
                            DigestAlgorithm digest, MaskGenerationFunction mgf)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // Create and initialize the cipher
    Cipher cipher = Cipher.getInstance(transportAlgorithm.transformation);
    if (transportAlgorithm == KeyTransportAlgorithm.RSAv15) {
      cipher.init(Cipher.ENCRYPT_MODE, encryptionCertificate.getPublicKey());
    } else {
      OAEPParameterSpec oaepParameters = new OAEPParameterSpec(
          digest.digest,
          "MGF1",
          // The RSA_OAEP_MGF1P algorithm implies the use of SHA-1 for the MGF digest algorithm
          new MGF1ParameterSpec(transportAlgorithm == KeyTransportAlgorithm.RSA_OAEP_MGF1P ? "SHA-1" : mgf.digest),
          // Use the default (empty byte[])
          PSpecified.DEFAULT
      );
      cipher.init(Cipher.ENCRYPT_MODE, encryptionCertificate.getPublicKey(), oaepParameters);
    }

    // Get the encrypted bytes for the key and return the result
    return cipher.doFinal(key.getEncoded());
  }

  /**
   * Extract the {@code EncryptedKey} element from the {@code EncryptedElement}. The key may be a sibling or child of
   * the {@code EncryptedData} element.
   *
   * @param encryptedAssertion an {@code EncryptedElement} containing the encrypted assertion
   * @return the {@code EncryptedKey} element containing the encrypted assertion encryption key
   */
  private EncryptedKeyType extractEncryptedAssertionEncryptionKey(EncryptedElementType encryptedAssertion) {
    // Get the EncryptedData element
    EncryptedDataType encryptedData = encryptedAssertion.getEncryptedData();

    // Extract the encrypted key value
    EncryptedKeyType encryptedKey = null;
    var encryptedKeys = encryptedAssertion.getEncryptedKey();
    if (!encryptedKeys.isEmpty()) {
      // Check for EncryptedKey as a sibling of EncryptedData
      encryptedKey = encryptedKeys.get(0);
    } else {
      var keyInfo = encryptedData.getKeyInfo();
      if (keyInfo != null) {
        var content = keyInfo.getContent();
        if (!content.isEmpty()) {
          JAXBElement<?> element = (JAXBElement<?>) content.get(0);
          encryptedKey = (EncryptedKeyType) element.getValue();
        }
      }
    }

    return encryptedKey;
  }

  /**
   * Finds the element that the XML signature should be inserted before in the DOM. This method is suitable when the XML
   * schema indicates the Signature should be inserted after the Issuer when the Issuer is the first optional element.
   *
   * @param toSign The XML element being signed
   * @return The XML node that the Signature should be inserted before or {@code null} if the Signature should be added
   * as the last child
   */
  private Node findSignatureInsertLocation(Element toSign) {
    NodeList children = toSign.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node n = children.item(i);
      if (n instanceof Element) {
        return n.getLocalName().equals("Issuer") ? n.getNextSibling() : n;
      }
    }

    return null;
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

  private Key generateAssertionEncryptionKey(EncryptionAlgorithm encryptionAlgorithm) throws NoSuchAlgorithmException {
    switch (encryptionAlgorithm) {
      case TripleDES -> {
        return KeyGenerator.getInstance("DESede")
                           .generateKey();
      }
      case AES128, AES128GCM -> {
        var keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
      }
      case AES192, AES192GCM -> {
        var keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(192);
        return keyGen.generateKey();
      }
      case AES256, AES256GCM -> {
        var keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
      }
      default -> throw new NoSuchAlgorithmException("Requested key for unsupported algorithm " + encryptionAlgorithm);
    }
  }

  private byte[] generateIV(EncryptionAlgorithm encryptionAlgorithm) {
    byte[] iv = new byte[encryptionAlgorithm.ivLength];
    new SecureRandom().nextBytes(iv);
    return iv;
  }

  private SubjectConfirmation parseConfirmation(SubjectConfirmationType subjectConfirmationType) {
    SubjectConfirmation subjectConfirmation = new SubjectConfirmation();
    SubjectConfirmationDataType data = subjectConfirmationType.getSubjectConfirmationData();
    if (data != null) {
      subjectConfirmation.address = data.getAddress();
      subjectConfirmation.inResponseTo = data.getInResponseTo();
      subjectConfirmation.notOnOrAfter = toZonedDateTime(data.getNotOnOrAfter());
      subjectConfirmation.recipient = data.getRecipient();
    }

    subjectConfirmation.method = ConfirmationMethod.fromSAMLFormat(subjectConfirmationType.getMethod());

    return subjectConfirmation;
  }

  private LogoutRequestParseResult parseLogoutRequest(byte[] xmlBytes) throws SAMLException {
    String xml = new String(xmlBytes, StandardCharsets.UTF_8);
    if (logger.isDebugEnabled()) {
      logger.debug("SAMLRequest XML is\n{}", xml);
    }

    LogoutRequestParseResult result = new LogoutRequestParseResult();
    result.document = newDocumentFromBytes(xmlBytes);
    result.logoutRequest = unmarshallFromDocument(result.document, LogoutRequestType.class);
    result.request = new LogoutRequest();
    result.request.xml = xml;
    result.request.id = result.logoutRequest.getID();
    result.request.issuer = result.logoutRequest.getIssuer().getValue();
    result.request.issueInstant = result.logoutRequest.getIssueInstant().toGregorianCalendar().toZonedDateTime();
    NameIDType nameId = result.logoutRequest.getNameID();
    if (nameId == null) {
      result.request.nameIdFormat = NameIDFormat.EmailAddress.toSAMLFormat();
    } else {
      result.request.nameIdFormat = nameId.getFormat();
    }
    List<String> sessionIndex = result.logoutRequest.getSessionIndex();
    result.request.sessionIndex = sessionIndex.isEmpty() ? null : sessionIndex.get(0);
    result.request.version = result.logoutRequest.getVersion();
    return result;
  }

  private LogoutResponseParseResult parseLogoutResponse(byte[] xmlBytes) throws SAMLException {
    String xml = new String(xmlBytes, StandardCharsets.UTF_8);
    if (logger.isDebugEnabled()) {
      logger.debug("SAMLRequest XML is\n{}", xml);
    }

    LogoutResponseParseResult result = new LogoutResponseParseResult();
    result.document = newDocumentFromBytes(xmlBytes);
    result.logoutResponse = unmarshallFromDocument(result.document, StatusResponseType.class);
    result.response = new LogoutResponse();
    result.response.xml = xml;
    result.response.id = result.logoutResponse.getID();
    result.response.issuer = result.logoutResponse.getIssuer().getValue();
    result.response.issueInstant = result.logoutResponse.getIssueInstant().toGregorianCalendar().toZonedDateTime();
    result.response.version = result.logoutResponse.getVersion();
    return result;
  }

  private AuthnRequestParseResult parseRequest(byte[] xmlBytes) throws SAMLException {
    String xml = new String(xmlBytes, StandardCharsets.UTF_8);
    if (logger.isDebugEnabled()) {
      logger.debug("SAMLRequest XML is\n{}", xml);
    }

    AuthnRequestParseResult result = new AuthnRequestParseResult();
    result.document = newDocumentFromBytes(xmlBytes);
    result.authnRequest = unmarshallFromDocument(result.document, AuthnRequestType.class);
    result.request = new AuthenticationRequest();
    result.request.acsURL = result.authnRequest.getAssertionConsumerServiceURL();
    result.request.id = result.authnRequest.getID();
    result.request.issuer = result.authnRequest.getIssuer().getValue();
    result.request.issueInstant = result.authnRequest.getIssueInstant().toGregorianCalendar().toZonedDateTime();
    NameIDPolicyType nameIdPolicyType = result.authnRequest.getNameIDPolicy();
    if (nameIdPolicyType == null) {
      result.request.nameIdFormat = NameIDFormat.EmailAddress.toSAMLFormat();
    } else {
      result.request.nameIdFormat = nameIdPolicyType.getFormat();
    }
    result.request.version = result.authnRequest.getVersion();
    result.request.xml = xml;
    return result;
  }

  private void signXML(PrivateKey privateKey, X509Certificate certificate, Algorithm algorithm,
                       String xmlSignatureC14nMethod, Element toSign, Node insertBefore,
                       boolean includeKeyInfo)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
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
    // KeyInfo is optional. Using the provided boolean, so we can test w/ and w/out
    KeyInfo ki = includeKeyInfo ? kif.newKeyInfo(Collections.singletonList(data)) : null;
    XMLSignature signature = factory.newXMLSignature(si, ki);

    signature.sign(dsc);
  }

  private void verifyEmbeddedSignature(Document document, KeySelector keySelector, SAMLRequest request)
      throws SAMLException {
    // Fix the IDs in the entire document per the suggestions at http://stackoverflow.com/questions/17331187/xml-dig-sig-error-after-upgrade-to-java7u25
    fixIDs(document.getDocumentElement());

    NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0) {
      throw new SignatureNotFoundException("Invalid SAML v2.0 operation. The signature is missing from the XML but is required.", request);
    }

    for (int i = 0; i < nl.getLength(); i++) {
      DOMValidateContext validateContext = new DOMValidateContext(keySelector, nl.item(i));
      XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
      try {
        XMLSignature signature = factory.unmarshalXMLSignature(validateContext);
        String algorith = signature.getSignedInfo().getSignatureMethod().getAlgorithm();

        if (algorith.equals(SignatureMethod.ECDSA_SHA1) ||
            algorith.equals(SignatureMethod.ECDSA_SHA224) ||
            algorith.equals(SignatureMethod.ECDSA_SHA256) ||
            algorith.equals(SignatureMethod.ECDSA_SHA384) ||
            algorith.equals(SignatureMethod.ECDSA_SHA512)) {
          checkFor_CVE_2022_21449(request, signature.getSignatureValue().getValue());
        }

        boolean valid = signature.validate(validateContext);
        if (!valid) {
          throw new SAMLException("Invalid SAML v2.0 operation. The signature is invalid.", request);
        }
      } catch (MarshalException e) {
        throw new SAMLException("Unable to verify XML signature in the SAML v2.0 XML. We couldn't unmarshall the XML Signature element.", request, e);
      } catch (XMLSignatureException e) {
        throw new SAMLException("Unable to verify XML signature in the SAML v2.0 XML. The signature was unmarshalled but we couldn't validate it. Possible reasons include a key was not provided that was eligible to verify the signature, or an un-expected exception occurred.", request, e);
      }
    }
  }

  private void verifyRequestSignature(SAMLRequestParameters requestParameters,
                                      RedirectBindingSignatureHelper signatureHelper, SAMLRequest request)
      throws SAMLException {
    Algorithm algorithm = Algorithm.fromURI(requestParameters.urlDecodedSigAlg());
    if (requestParameters.Signature == null || algorithm == null || signatureHelper.publicKey() == null) {
      throw new SignatureNotFoundException("You must specify a signature, key and algorithm if you want to verify the SAML request signature", request);
    }

    try {
      // We are assuming validation has already been performed to confirm the correct parameters are in the queryString.
      String parameters = "SAMLRequest=" + requestParameters.SAMLRequest;
      if (requestParameters.RelayState != null) {
        parameters += "&RelayState=" + requestParameters.RelayState;
      }
      parameters += "&SigAlg=" + requestParameters.SigAlg;

      Signature sig = Signature.getInstance(algorithm.name);
      sig.initVerify(signatureHelper.publicKey());
      sig.update(parameters.getBytes(StandardCharsets.UTF_8));
      byte[] signature = Base64.getMimeDecoder().decode(requestParameters.urlDecodedSignature().getBytes(StandardCharsets.UTF_8));

      if (algorithm.uri.equals(SignatureMethod.ECDSA_SHA1) ||
          algorithm.uri.equals(SignatureMethod.ECDSA_SHA224) ||
          algorithm.uri.equals(SignatureMethod.ECDSA_SHA256) ||
          algorithm.uri.equals(SignatureMethod.ECDSA_SHA384) ||
          algorithm.uri.equals(SignatureMethod.ECDSA_SHA512)) {
        checkFor_CVE_2022_21449(request, signature);
      }

      if (!sig.verify(signature)) {
        throw new SAMLException("Invalid SAML v2.0 operation. The signature is invalid.", request);
      }
    } catch (GeneralSecurityException e) {
      throw new SAMLException("Unable to verify signature", request, e);
    }
  }

  private static class AuthnRequestParseResult {
    public AuthnRequestType authnRequest;

    public Document document;

    public AuthenticationRequest request;
  }

  private static class LogoutRequestParseResult {
    public Document document;

    public LogoutRequestType logoutRequest;

    public LogoutRequest request;
  }

  private static class LogoutResponseParseResult {
    public Document document;

    public StatusResponseType logoutResponse;

    public LogoutResponse response;
  }
}
