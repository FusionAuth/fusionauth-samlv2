/*
 * Copyright (c) 2013-2025, Inversoft Inc., All Rights Reserved
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

import javax.xml.XMLConstants;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.Assertion;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.Binding;
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
import io.fusionauth.samlv2.domain.NameIDFormat;
import io.fusionauth.samlv2.domain.ResponseStatus;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.SignatureLocation;
import io.fusionauth.samlv2.domain.SignatureNotFoundException;
import io.fusionauth.samlv2.domain.Status;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.LogoutRequestType;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.StatusResponseType;
import io.fusionauth.samlv2.util.SAMLTools;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.Unmarshaller;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import sun.security.util.KnownOIDs;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Tests the default authentication service.
 *
 * @author Brian Pontarelli
 */
@SuppressWarnings({"unchecked"})
@Test(groups = "unit")
public class DefaultSAMLv2ServiceTest {
  private String assertionSigned;

  private String assertionUnsigned;

  private String baseXml;

  private String encryptedSigned;

  private String encryptedUnsigned;

  private KeyPair encryptionKeyPair;

  private KeyPair signingKeyPair;

  @DataProvider(name = "BooleanTriState")
  public Object[][] BooleanTriState() {
    return new Object[][]{
        {Boolean.TRUE},
        {Boolean.FALSE},
        {null}
    };
  }

  @Test
  public void assertionDecryptionDefaults() throws Exception {
    // If RSA-OAEP Digest and Mask Generation Function are not specified by XML, decryption should fall back to the defaults

    // Build a known key pair.
    KeyFactory factory = KeyFactory.getInstance("RSA");
    // The public key is not required for this test, but it may be useful to modify or expand this test in the future
    // PublicKey publicKey = factory.generatePublic(new RSAPublicKeySpec(new BigInteger("21734648244307152755738902242704624429675455693104061482953980655823499524284217582577935962219675181839097134429878676848067944269649003417313253763145613039845156858929146350893510281417425701635390227843218753386852942958087790126591910892081707753005524949329857277363222746280909051526362184081185954039703446436022345307092346517413518280909483768946131477611274390374625720745000173012484689181319542884541163003470909355448313533318136237678943263133529991715284549440616270148923866161198748312992261382455526114770464413102345807150728423473869759031086596301998397561122681012070445972165920288084712186321"), new BigInteger("65537")));
    PrivateKey privateKey = factory.generatePrivate(
        new RSAPrivateKeySpec(
            new BigInteger("21734648244307152755738902242704624429675455693104061482953980655823499524284217582577935962219675181839097134429878676848067944269649003417313253763145613039845156858929146350893510281417425701635390227843218753386852942958087790126591910892081707753005524949329857277363222746280909051526362184081185954039703446436022345307092346517413518280909483768946131477611274390374625720745000173012484689181319542884541163003470909355448313533318136237678943263133529991715284549440616270148923866161198748312992261382455526114770464413102345807150728423473869759031086596301998397561122681012070445972165920288084712186321"),
            new BigInteger("2627246950446332058699110175423135552922607992443510918533979809198372876869242896214083780043399404771798030104421912476774863886112568550161826087731198353627009668377202151330979270479101063648863411278727725778272563805391938498601722966981572071033305898173415465329072899217806147766785803779409419532480730005663347830294097525463269173509836986107754922630483079886942638729284878709865541937468056706189367357847138095922090696226255189351459450052835991176393120796259048519702721129794393046985282164398590601866202429118551867608688177161937729422431790107723304390299253182892873596285122556471119338537")
        )
    );

    // Load an unsigned sample response encrypted using the associated public certificate from above
    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse-assertionDecryptionDefaults.txt"));
    String encodedXML = new String(ba, StandardCharsets.UTF_8);

    // Parse the encrypted sample response
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse parsedResponse = service.parseResponse(
        encodedXML,
        false, null,
        true, privateKey
    );

    // Load a known encoded sample response from file and parse it
    ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba, StandardCharsets.UTF_8);
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    // Verify the parsed encrypted response matches the original pulled from file
    // The Assertion ID attributes were generated with the sample encoded responses, but the rest of the assertions are identical.
    parsedResponse.assertions.get(0).id = response.assertions.get(0).id;

    // Sync up the authnInstant since it is not in the encodedResponse
    parsedResponse.authnInstant = response.authnInstant;

    // Assert the two values are equal
    assertEquals(parsedResponse, response);
  }

  @DataProvider(name = "assertionEncryption")
  public Object[][] assertionEncryption() {
    return new Object[][]{
        {EncryptionAlgorithm.AES128, KeyLocation.Child, KeyTransportAlgorithm.RSAv15, DigestAlgorithm.SHA256, null},
        {EncryptionAlgorithm.AES128, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP_MGF1P, DigestAlgorithm.SHA256, null},
        {EncryptionAlgorithm.AES128, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1},
        {EncryptionAlgorithm.AES128, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA512, MaskGenerationFunction.MGF1_SHA256},
        {EncryptionAlgorithm.AES192, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1},
        {EncryptionAlgorithm.AES256, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1},
        {EncryptionAlgorithm.AES256, KeyLocation.Sibling, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1},
        {EncryptionAlgorithm.AES128GCM, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1},
        {EncryptionAlgorithm.AES192GCM, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1},
        {EncryptionAlgorithm.AES256GCM, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1},
        {EncryptionAlgorithm.TripleDES, KeyLocation.Child, KeyTransportAlgorithm.RSA_OAEP, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1_SHA1}
    };
  }

  @BeforeClass
  public void beforeClass() throws Exception {
    System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
    loadKeys();
    loadAssertionTemplates();
  }

  @DataProvider(name = "bindings")
  public Object[][] bindings() {
    return new Object[][]{
        {Binding.HTTP_Redirect},
        {Binding.HTTP_POST}
    };
  }

  @Test
  public void buildIdPMetaData() throws Exception {
    MetaData metaData = new MetaData();
    metaData.id = UUID.randomUUID().toString();
    metaData.entityId = "https://fusionauth.io/samlv2/" + metaData.id;
    metaData.idp = new IDPMetaData();
    metaData.idp.wantAuthnRequestsSigned = true;
    metaData.idp.postBindingSignInEndpoints.add("https://fusionauth.io/samlv2/login/POST");
    metaData.idp.redirectBindingSignInEndpoints.add("https://fusionauth.io/samlv2/login/REDIRECT");

    metaData.idp.postBindingLogoutEndpoints.add("https://fusionauth.io/samlv2/logout/POST");
    metaData.idp.redirectBindingLogoutEndpoints.add("https://fusionauth.io/samlv2/logout/REDIRECT");

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    Certificate cert = CertificateTools.fromKeyPair(kp, Algorithm.RS256, "FusionAuth");
    metaData.idp.certificates.add(cert);

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String xml = service.buildMetadataResponse(metaData);
    // System.out.println(xml);
    assertTrue(xml.contains("_" + metaData.id));
    assertTrue(xml.contains(metaData.entityId));
    assertTrue(xml.contains(metaData.idp.postBindingSignInEndpoints.get(0)));
    assertTrue(xml.contains(metaData.idp.postBindingLogoutEndpoints.get(0)));
    assertTrue(xml.contains(metaData.idp.redirectBindingLogoutEndpoints.get(0)));
    assertTrue(xml.contains(metaData.idp.redirectBindingLogoutEndpoints.get(0)));
    assertTrue(xml.contains("<ns2:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"));

    // Now parse it
    MetaData parsed = service.parseMetaData(xml);
    assertEquals(parsed.id, "_" + metaData.id);
    assertEquals(parsed.entityId, metaData.entityId);
    assertEquals(parsed.idp.postBindingSignInEndpoints, metaData.idp.postBindingSignInEndpoints);
    assertEquals(parsed.idp.redirectBindingSignInEndpoints, metaData.idp.redirectBindingSignInEndpoints);
    assertEquals(parsed.idp.postBindingLogoutEndpoints, metaData.idp.postBindingLogoutEndpoints);
    assertEquals(parsed.idp.redirectBindingLogoutEndpoints, metaData.idp.redirectBindingLogoutEndpoints);
    assertEquals(parsed.idp.certificates, metaData.idp.certificates);
  }

  @Test(dataProvider = "bindings")
  public void buildLogoutRequest(Binding binding) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey privateKey = kp.getPrivate();
    X509Certificate certificate = generateX509Certificate(kp, "SHA256withRSA");

    LogoutRequest logoutRequest = new LogoutRequest();
    logoutRequest.id = "_1245";
    logoutRequest.issuer = "https://acme.corp/saml";
    logoutRequest.sessionIndex = "42";
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    String rawRequest = binding == Binding.HTTP_Redirect
        ? service.buildRedirectLogoutRequest(logoutRequest, "Relay-State-String", true, privateKey, Algorithm.RS256)
        : service.buildPostLogoutRequest(logoutRequest, true, privateKey, certificate, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);

    assertNotNull(rawRequest);

    String samlRequest = rawRequest;
    if (binding == Binding.HTTP_Redirect) {
      int start = samlRequest.indexOf('=');
      int end = samlRequest.indexOf('&');
      samlRequest = samlRequest.substring(start + 1, end);
      samlRequest = URLDecoder.decode(samlRequest, StandardCharsets.UTF_8);
    }

    byte[] bytes = binding == Binding.HTTP_Redirect
        ? SAMLTools.decodeAndInflate(samlRequest)
        : SAMLTools.decode(samlRequest);

    JAXBContext context = JAXBContext.newInstance(AuthnRequestType.class);
    Unmarshaller unmarshaller = context.createUnmarshaller();

    JAXBElement<LogoutRequestType> element = (JAXBElement<LogoutRequestType>) unmarshaller.unmarshal(new ByteArrayInputStream(bytes));
    assertEquals(element.getValue().getID(), "_1245");
    assertEquals(element.getValue().getIssuer().getValue(), "https://acme.corp/saml");
    assertEquals(element.getValue().getSessionIndex().size(), 1);
    assertEquals(element.getValue().getSessionIndex().get(0), "42");
    assertEquals(element.getValue().getVersion(), "2.0");

    // For HTTP Redirect, pull out the RelayState and SigAlg values from the request parameter.
    if (binding == Binding.HTTP_Redirect) {
      // Unwind the RelayState
      int start = rawRequest.indexOf("RelayState=");
      int end = rawRequest.indexOf('&', start);
      String relayState = URLDecoder.decode(rawRequest.substring(start + "RelayState=".length(), end), StandardCharsets.UTF_8);
      assertEquals(relayState, "Relay-State-String");

      // Unwind the SigAlg
      start = rawRequest.indexOf("SigAlg=");
      end = rawRequest.indexOf('&', start);
      String sigAlg = URLDecoder.decode(rawRequest.substring(start + "SigAlg=".length(), end), StandardCharsets.UTF_8);
      assertEquals(sigAlg, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }
  }

  @Test(dataProvider = "bindings")
  public void buildLogoutResponse(Binding binding) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey privateKey = kp.getPrivate();
    X509Certificate certificate = generateX509Certificate(kp, "SHA256withRSA");

    LogoutResponse logoutResponse = new LogoutResponse();
    logoutResponse.id = "_1245";
    logoutResponse.issuer = "https://acme.corp/saml";
    logoutResponse.sessionIndex = "42";
    logoutResponse.status = new Status();
    logoutResponse.status.code = ResponseStatus.Success;
    logoutResponse.status.message = "Ok";
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    String rawResponse = binding == Binding.HTTP_Redirect
        ? service.buildRedirectLogoutResponse(logoutResponse, "Relay-State-String", true, privateKey, Algorithm.RS256)
        : service.buildPostLogoutResponse(logoutResponse, true, privateKey, certificate, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);

    assertNotNull(rawResponse);

    String samlResponse = rawResponse;
    if (binding == Binding.HTTP_Redirect) {
      int start = samlResponse.indexOf('=');
      int end = samlResponse.indexOf('&');
      samlResponse = samlResponse.substring(start + 1, end);
      samlResponse = URLDecoder.decode(samlResponse, StandardCharsets.UTF_8);
    }

    byte[] bytes = binding == Binding.HTTP_Redirect
        ? SAMLTools.decodeAndInflate(samlResponse)
        : SAMLTools.decode(samlResponse);

    JAXBContext context = JAXBContext.newInstance(AuthnRequestType.class);
    Unmarshaller unmarshaller = context.createUnmarshaller();

    JAXBElement<StatusResponseType> element = (JAXBElement<StatusResponseType>) unmarshaller.unmarshal(new ByteArrayInputStream(bytes));
    assertEquals(element.getValue().getID(), "_1245");
    assertEquals(element.getValue().getIssuer().getValue(), "https://acme.corp/saml");
    assertEquals(element.getValue().getVersion(), "2.0");

    // For HTTP Redirect, pull out the RelayState and SigAlg values from the request parameter.
    if (binding == Binding.HTTP_Redirect) {
      // Unwind the RelayState
      int start = rawResponse.indexOf("RelayState=");
      int end = rawResponse.indexOf('&', start);
      String relayState = URLDecoder.decode(rawResponse.substring(start + "RelayState=".length(), end), StandardCharsets.UTF_8);
      assertEquals(relayState, "Relay-State-String");

      // Unwind the SigAlg
      start = rawResponse.indexOf("SigAlg=");
      end = rawResponse.indexOf('&', start);
      String sigAlg = URLDecoder.decode(rawResponse.substring(start + "SigAlg=".length(), end), StandardCharsets.UTF_8);
      assertEquals(sigAlg, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }
  }

  @Test
  public void buildLogoutResponse_signatureFollowsIssuer() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey privateKey = kp.getPrivate();
    X509Certificate certificate = generateX509Certificate(kp, "SHA256withRSA");

    LogoutResponse logoutResponse = new LogoutResponse();
    logoutResponse.id = "_1245";
    logoutResponse.issuer = "https://acme.corp/saml";
    logoutResponse.sessionIndex = "42";
    logoutResponse.status = new Status();
    logoutResponse.status.code = ResponseStatus.Success;
    logoutResponse.status.message = "Ok";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String samlRequest = service.buildPostLogoutResponse(logoutResponse, true, privateKey, certificate, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    assertNotNull(samlRequest);

    byte[] bytes = SAMLTools.decode(samlRequest);
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(bytes));

    // Confirm that the Signature element immediately follows the Issuer element as required by the spec
    Element issuer = (Element) doc.getElementsByTagName("Issuer").item(0);
    Element signature = (Element) issuer.getNextSibling();
    assertEquals(signature.getTagName(), "Signature");
  }

  @Test(dataProvider = "BooleanTriState")
  public void buildPostAuthnRequest_forceAuthn(Boolean forceAuthN) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey privateKey = kp.getPrivate();
    X509Certificate certificate = generateX509Certificate(kp, "SHA256withRSA");

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";
    request.forceAuthn = forceAuthN;

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    // Build a post request
    String postRequest = service.buildPostAuthnRequest(request, true, privateKey, certificate, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    assertNotNull(postRequest);

    // Parse it and ensure it matches the input
    AuthenticationRequest actualPostRequest = service.parseRequestPostBinding(postRequest, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(certificate.getPublicKey()), true));
    assertEquals(actualPostRequest.forceAuthn, forceAuthN);

    // Build a redirect request
    String redirectRequest = service.buildRedirectAuthnRequest(request, "Relay-State", true, privateKey, Algorithm.RS256);
    assertNotNull(redirectRequest);

    // Parse it as a redirect request to ensure it matches the input
    AuthenticationRequest actualRedirectRequest = service.parseRequestRedirectBinding(redirectRequest, authRequest -> new TestRedirectBindingSignatureHelper(certificate.getPublicKey(), true));
    assertEquals(actualRedirectRequest.forceAuthn, forceAuthN);
  }

  @Test
  public void buildPostAuthnRequest_signatureFollowsIssuer() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey privateKey = kp.getPrivate();
    X509Certificate certificate = generateX509Certificate(kp, "SHA256withRSA");

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String samlRequest = service.buildPostAuthnRequest(request, true, privateKey, certificate, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    assertNotNull(samlRequest);

    byte[] bytes = SAMLTools.decode(samlRequest);
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(bytes));

    // Confirm that the Signature element immediately follows the Issuer element as required by the spec
    Element issuer = (Element) doc.getElementsByTagName("Issuer").item(0);
    Element signature = (Element) issuer.getNextSibling();
    assertEquals(signature.getTagName(), "Signature");
  }

  @Test
  public void buildPostLogoutRequest_signatureFollowsIssuer() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey privateKey = kp.getPrivate();
    X509Certificate certificate = generateX509Certificate(kp, "SHA256withRSA");

    LogoutRequest request = new LogoutRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String samlRequest = service.buildPostLogoutRequest(request, true, privateKey, certificate, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    assertNotNull(samlRequest);

    byte[] bytes = SAMLTools.decode(samlRequest);
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new ByteArrayInputStream(bytes));

    // Confirm that the Signature element immediately follows the Issuer element as required by the spec
    Element issuer = (Element) doc.getElementsByTagName("Issuer").item(0);
    Element signature = (Element) issuer.getNextSibling();
    assertEquals(signature.getTagName(), "Signature");
  }

  @Test(dataProvider = "bindings")
  public void buildRedirectAuthnRequest(Binding binding) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey privateKey = kp.getPrivate();
    X509Certificate certificate = generateX509Certificate(kp, "SHA256withRSA");

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    String rawRequest = binding == Binding.HTTP_Redirect
        ? service.buildRedirectAuthnRequest(request, "Relay-State-String", true, privateKey, Algorithm.RS256)
        : service.buildPostAuthnRequest(request, true, privateKey, certificate, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    assertNotNull(rawRequest);

    String samlRequest = rawRequest;
    if (binding == Binding.HTTP_Redirect) {
      int start = samlRequest.indexOf('=');
      int end = samlRequest.indexOf('&');
      samlRequest = samlRequest.substring(start + 1, end);
      samlRequest = URLDecoder.decode(samlRequest, StandardCharsets.UTF_8);
    }

    byte[] bytes = binding == Binding.HTTP_Redirect
        ? SAMLTools.decodeAndInflate(samlRequest)
        : SAMLTools.decode(samlRequest);

    JAXBContext context = JAXBContext.newInstance(AuthnRequestType.class);
    Unmarshaller unmarshaller = context.createUnmarshaller();

    JAXBElement<AuthnRequestType> fromEncoded = (JAXBElement<AuthnRequestType>) unmarshaller.unmarshal(new ByteArrayInputStream(bytes));
    assertEquals(fromEncoded.getValue().getID(), "foobarbaz");
    assertEquals(fromEncoded.getValue().getIssuer().getValue(), "https://local.fusionauth.io");
    assertEquals(fromEncoded.getValue().getVersion(), "2.0");
    assertFalse(fromEncoded.getValue().getNameIDPolicy().isAllowCreate());

    // For HTTP Redirect, pull out the RelayState and SigAlg values from the request parameter.
    if (binding == Binding.HTTP_Redirect) {
      // Unwind the RelayState
      int start = rawRequest.indexOf("RelayState=");
      int end = rawRequest.indexOf('&', start);
      String relayState = URLDecoder.decode(rawRequest.substring(start + "RelayState=".length(), end), StandardCharsets.UTF_8);
      assertEquals(relayState, "Relay-State-String");

      // Unwind the SigAlg
      start = rawRequest.indexOf("SigAlg=");
      end = rawRequest.indexOf('&', start);
      String sigAlg = URLDecoder.decode(rawRequest.substring(start + "SigAlg=".length(), end), StandardCharsets.UTF_8);
      assertEquals(sigAlg, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }
  }

  @Test
  public void buildSPMetaData() throws Exception {
    MetaData metaData = new MetaData();
    metaData.id = UUID.randomUUID().toString();
    metaData.entityId = "https://fusionauth.io/samlv2/sp/" + metaData.id;
    metaData.sp = new SPMetaData();
    metaData.sp.acsEndpoint = "https://fusionauth.io/oauth2/callback";
    metaData.sp.nameIDFormat = NameIDFormat.EmailAddress;

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String xml = service.buildMetadataResponse(metaData);
    // System.out.println(xml);
    assertTrue(xml.contains("_" + metaData.id));
    assertTrue(xml.contains(metaData.entityId));
    assertTrue(xml.contains(metaData.sp.acsEndpoint));
    assertTrue(xml.contains(metaData.sp.nameIDFormat.toSAMLFormat()));
    assertTrue(xml.contains("<ns2:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"));

    // Now parse it
    MetaData parsed = service.parseMetaData(xml);
    assertEquals(parsed.id, "_" + metaData.id);
    assertEquals(parsed.entityId, metaData.entityId);
    assertEquals(parsed.sp.acsEndpoint, metaData.sp.acsEndpoint);
    assertEquals(parsed.sp.nameIDFormat, metaData.sp.nameIDFormat);
  }

  @Test(dataProvider = "bindings")
  public void hacking_CVE_2022_21449(Binding binding) throws Exception {
    // Attempt to hack the signature for CVE-2022-21449
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(256);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String queryString;
    if (binding == Binding.HTTP_Redirect) {
      queryString = service.buildRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.ES256);
    } else {
      X509Certificate cert = generateX509Certificate(kp, "SHA256withECDSA");
      queryString = service.buildPostAuthnRequest(request, true, kp.getPrivate(), cert, Algorithm.ES256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    }

    // Hack the signature
    int start = queryString.indexOf("Signature=");
    int end = queryString.indexOf("&", start);

    // ECDSA-Sig-Value ::= SEQUENCE {
    //   r  INTEGER,
    //   s  INTEGER
    // }

    byte[] hackedBytes = new byte[]{48, 6, 2, 1, 0, 2, 1, 0};
    String hackedSig = Base64.getUrlEncoder().encodeToString(hackedBytes);
    String hacked;
    if (binding == Binding.HTTP_Redirect) {
      hacked = queryString.substring(0, start) + "Signature=" + hackedSig;
      if (end != -1) {
        hacked += queryString.substring(end);
      }

      try {
        service.parseRequestRedirectBinding(hacked, authRequest -> new TestRedirectBindingSignatureHelper(kp.getPublic(), true));
        fail("This should have exploded.");
      } catch (SAMLException ignore) {
      }
    } else {
      Document document = parseDocument(queryString);
      Node signature = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
      Node signatureValue = signature.getFirstChild().getNextSibling();
      signatureValue.setTextContent(hackedSig);
      String hackedDocument = SAMLTools.marshallToString(document);
      String hackedDocumentEncoded = new String(Base64.getEncoder().encode(hackedDocument.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
      try {
        service.parseRequestPostBinding(hackedDocumentEncoded, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(kp.getPublic()), true));
        fail("This should have exploded.");
      } catch (SAMLException ignore) {
      }
    }
  }

  @DataProvider(name = "maxLineLength")
  public Object[][] maxLineLength() {
    return new Object[][]{
        {42},
        {64},
        {76},
        {96},
        {128}
    };
  }

  @Test(dataProvider = "bindings")
  public void parseLogout_Request_raw(Binding binding) throws Exception {
    byte[] bytes = binding == Binding.HTTP_Redirect
        ? Files.readAllBytes(Paths.get("src/test/xml/encoded/logout-request.txt"))
        : Files.readAllBytes(Paths.get("src/test/xml/encoded/logout-request-embedded-signature.txt"));

    String encodedXML = new String(bytes, StandardCharsets.UTF_8);

    X509Certificate certificate;
    String redirectSignature = Files.readString(Paths.get("src/test/xml/signature/logout-request.txt"));
    String x509encoded = "MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==";
    try (InputStream is = new ByteArrayInputStream(Base64.getMimeDecoder().decode(x509encoded))) {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      certificate = (X509Certificate) factory.generateCertificate(is);
    }

    assertNotNull(certificate);
    PublicKey publicKey = certificate.getPublicKey();

    // For HTTP Redirect binding
    String queryString = "SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8) +
        "&RelayState=" + URLEncoder.encode("http://sp.example.com/relaystate", StandardCharsets.UTF_8) +
        "&SigAlg=" + URLEncoder.encode(Algorithm.RS1.uri, StandardCharsets.UTF_8) +
        "&Signature=" + URLEncoder.encode(redirectSignature, StandardCharsets.UTF_8);

    // Testing purposes, signatures can't be verified currently, TBD if this is a bug or just invalid signatures.
    // - Disable signature verification for now.
    boolean verifySignature = false;
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    LogoutRequest request = binding == Binding.HTTP_Redirect
        ? service.parseLogoutRequestRedirectBinding(queryString, logoutRequest -> new TestRedirectBindingSignatureHelper(publicKey, verifySignature))
        : service.parseLogoutRequestPostBinding(encodedXML, logoutRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), verifySignature));

    assertEquals(request.id, binding == Binding.HTTP_Redirect
        ? "ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d"
        : "pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1");
    assertEquals(request.issuer, "http://sp.example.com/demo1/metadata.php");
    assertEquals(request.nameIdFormat, NameIDFormat.Transient.toSAMLFormat());
    assertEquals(request.version, "2.0");

    String expectedXML = binding == Binding.HTTP_Redirect
        ? new String(Files.readAllBytes(Paths.get("src/test/xml/logout-request.xml")))
        : new String(Files.readAllBytes(Paths.get("src/test/xml/logout-request-embedded-signature.xml")));
    assertEquals(request.xml.replace("\r\n", "\n"), expectedXML.replace("\r\n", "\n"));
  }

  @Test
  public void parseMetaData() throws Exception {
    byte[] buf = Files.readAllBytes(Paths.get("src/test/xml/metadata.xml"));
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    MetaData metaData = service.parseMetaData(new String(buf, StandardCharsets.UTF_8));
    assertEquals(metaData.idp.certificates.size(), 3);

    buf = Files.readAllBytes(Paths.get("src/test/xml/metadata-2.xml"));
    metaData = service.parseMetaData(new String(buf, StandardCharsets.UTF_8));
    assertEquals(metaData.idp.certificates.size(), 1);
  }

  @Test(enabled = false)
  public void parseRequest_compassSecurity() throws Exception {
    String encodedXML = "PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIg0KICAgICAgICAgICAgICAgICAgICB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzdmZTUxMGNjOGU1MWFhNDE1NThhIg0KICAgICAgICAgICAgICAgICAgICBJc3N1ZUluc3RhbnQ9IjIwMjEtMDEtMjFUMTY6NDY6MDVaIiBQcm92aWRlck5hbWU9IlNpbXBsZSBTQU1MIFNlcnZpY2UgUHJvdmlkZXIiDQogICAgICAgICAgICAgICAgICAgIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cDovL2xvY2FsaG9zdDo3MDcwL3NhbWwvc3NvIg0KICAgICAgICAgICAgICAgICAgICBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo5MDExL3NhbWx2Mi9sb2dpbi81YjJlNDgzZi03NTcyLTQ4NzktODE3ZS0xYTkwYWM0NGU3NTciDQogICAgICAgICAgICAgICAgICAgIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCIgVmVyc2lvbj0iMi4wIj4NCiAgPHNhbWw6SXNzdWVyPnVybjpleGFtcGxlOnNwPC9zYW1sOklzc3Vlcj4NCiAgPFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQogICAgPFNpZ25lZEluZm8+DQogICAgICA8Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPg0KICAgICAgPFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz4NCiAgICAgIDxSZWZlcmVuY2UgVVJJPSIjXzdmZTUxMGNjOGU1MWFhNDE1NThhIj4NCiAgICAgICAgPFRyYW5zZm9ybXM+DQogICAgICAgICAgPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+DQogICAgICAgICAgPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPg0KICAgICAgICA8L1RyYW5zZm9ybXM+DQogICAgICAgIDxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCiAgICAgICAgPERpZ2VzdFZhbHVlPjV4V2cvaWRqOGpNV2Z3ZWRmaksyQkVZa2QveUxXY2pNa2ZKK1ZmOHQrRkE9PC9EaWdlc3RWYWx1ZT4NCiAgICAgIDwvUmVmZXJlbmNlPg0KICAgIDwvU2lnbmVkSW5mbz4NCiAgICA8U2lnbmF0dXJlVmFsdWU+DQogICAgICBsZ05CSEZ4UHFueHVKRmVRa0cwN3dNY0JwZll3TkVBc2pMeWpQTTBsQit5Nm8rNEtDSzN0U2padXVSUVlNWTRJb3J6Uk95b3piZGtsRitCT2UxL0tKNFhxRGhFaXFlbUEyTGszcEliakJQbit6NDdGcER0NWdsQUVxY3NmMlI2RDhKTndkNWJxSmgxYnVITXNUQ3dIOFhPVHZpdHlxQXZrZmp4WVhNU290SDFWSWxrRWxjZFF6aXA5ZlhsZW1ZdExCdXoybG5sTHYyS01DSkRpYTlQTzZrSHQySTRBL2s0WXBNRmx2NlF0aGlPcjdlVjROOWIxVk43VUxYRHJlUS9OUDhtZWdtWGVBcWxaMC81VnlXdGRYQ1E0QUlSUVlUeW5mTlZ3TDA1VG5JOXNYZDl5WTdPbXk5WVJwdEYzaHZBWVFqd0t1ak90bjNGUnJNSldKMzRha3c9PQ0KICAgIDwvU2lnbmF0dXJlVmFsdWU+DQogICAgPEtleUluZm8+DQogICAgICA8WDUwOURhdGE+DQogICAgICAgIDxYNTA5Q2VydGlmaWNhdGU+DQogICAgICAgICAgTUlJRFV6Q0NBanVnQXdJQkFnSUpBUEowbUE2V3pPcHZNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HQXhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJRXdwRFlXeHBabTl5Ym1saE1SWXdGQVlEVlFRSEV3MVRZVzRnUm5KaGJtTnBjMk52TVJBd0RnWURWUVFLRXdkS1lXNXJlVU52TVJJd0VBWURWUVFERXdsc2IyTmhiR2h2YzNRd0hoY05NVFF3TXpFeU1UazBOak16V2hjTk1qY3hNVEU1TVRrME5qTXpXakJnTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCeE1OVTJGdUlFWnlZVzVqYVhOamJ6RVFNQTRHQTFVRUNoTUhTbUZ1YTNsRGJ6RVNNQkFHQTFVRUF4TUpiRzlqWVd4b2IzTjBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRsTkR5NERSMnRoWjJERGNpSVRvZlVwd1laY25Yay85cHFEdDhWMTZqQkQwMnVPZC9UZHlzZ2lLTGpyWlpiQy9YME9YMUVGZTVkTjY1VXJMT0RRQkJ6WjMvOFBZejY4MTlNS2M5aXJWOCs3MzJINWRHd3pnbVlCWUQrcXFmNEJjUjM2TDdUam1Pd2prZSsxY01jR2crV1hWU1hRTS9kalN4aFFIaldOamtSdDFUL21MZmxxTXFwb3B6Y21BUFFETEVIRXJ0dWFtOVh0dWRqaUZNOHI1anp2bXUvVXBJUGliYndBWThxM3NUUHBFN0pCTHI2SXk0cEJBY2lMbFhhNE5yRFE4YUw4akZwaWhqdm0rdUhWTUhNR215bkdpY0dRTGdyRktPV3M2NTVtVlZXWGZET2U2SjVwaUJYcjFteW5uQnN0ZGRTYWxaNWFMQVdGOGc2c3pmUUlEQVFBQm94QXdEakFNQmdOVkhSTUJBZjhFQWpBQU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ2xaeStnTVlrTmZvK2RRakV1dmJ2eDYyTU1SM1dka3BmZXk0M1pnUHF4MTh2cEcwUDdhSXFUeWJreFRraGkvQXc4cExEY0l2QVBaSHFsTWZMQ05Cci80K3NucXJMbzNPaUdaSTFobDlRT0czaFFta3JqVDEwaGx5WFJTM29UbmpENWJoRGoraW5iRzFpOVFSSzdQTzBQUXFXaElLZ3J0THlZcDNXdlM2WjljWVh3UXQ1RmNZYmhLcCtDK2t2Q3pxK1RmYlFhbWx2ZWhXakJVTlIyN0NFMTFNLy9XVEYwbmZiT0Z1MzJFQzZrQjBFR2Q2UFRJd2h0eTJ6SHhnKyt1WU1qQVVMK1pOdU5pYU1jMzU1b1h2THRoMXE1cmszR2EzdW5wQmptUTdvYlUyLzQvV2RKblBmdmxEMmt0QVYvUzVkVlNLU0RObWthZzhJWDBuSGIvMUZODQogICAgICAgIDwvWDUwOUNlcnRpZmljYXRlPg0KICAgICAgPC9YNTA5RGF0YT4NCiAgICA8L0tleUluZm8+DQogIDwvU2lnbmF0dXJlPg0KICA8c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPg0KICA8c2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0IENvbXBhcmlzb249ImV4YWN0Ij4NCiAgICA8c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydA0KICAgIDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj4NCiAgPC9zYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQ+DQo8L3NhbWxwOkF1dGhuUmVxdWVzdD4=";
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    PublicKey publicKey = KeyFactory.getInstance("RSA")
                                    .generatePublic(new RSAPublicKeySpec(
                                        new BigInteger("23016430918823899869174537266594866915196701755262955756947374683306171050449785978041642070945082562110926617344211216571596575890159654912559343561454566120924390651417182396241104494630512996615232908509829811443784313485862019497373006302688901954848508137355590138442254765794572625586049567608157223736747587462558785268970406066201827350377828581492579969240135441642716939367190425379788145244337250560138881783025442595121210838086638484878363941229167629103738547784336822433469701246494321129732432091196962736034404069520496182669787723781485938596516343326251546340541402004104537790138422441873446220669"),
                                        new BigInteger("65537")));
    TestPostBindingSignatureHelper signatureHelper = new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), true);
    AuthenticationRequest request = service.parseRequestPostBinding(encodedXML, authRequest -> signatureHelper);

    assertEquals(request.id, "_7fe510cc8e51aa41558a");
    assertEquals(request.issuer, "urn:example:sp");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
  }

  @Test
  public void parseRequest_expandedEntity() throws Exception {
    // Expanded entity, fail. The entity definition is within the DOCTYPE, which is not allowed, the error will be with regards to the DOCTYPE.
    try {
      DefaultSAMLv2Service service = new DefaultSAMLv2Service();
      byte[] xml = Files.readAllBytes(Paths.get("src/test/xml/authn-request-expanded-entity.xml"));
      String deflated = SAMLTools.deflateAndEncode(xml);
      String queryString = "SAMLRequest=" + URLEncoder.encode(deflated, StandardCharsets.UTF_8);
      AuthenticationRequest request = service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper());
      fail("Expected an exception because we are declaring a DOCTYPE and expanding an entity. The issuer is now set to [" + request.issuer + "] which is not good.");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Unable to parse SAML v2.0 document.");
      assertEquals(e.getCause().getClass().getCanonicalName(), "org.xml.sax.SAXParseException");
      assertEquals(e.getCause().getMessage(), "DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.");
    }
  }

  @Test
  public void parseRequest_externalDTD() throws Exception {
    // Load an external DTD, fail, this is defined within the DOCTYPE, so the error will be with regards to the DOCTYPE.
    Path tempFile = null;
    try {
      tempFile = Files.createTempFile("readThisFile", ".tmp");
      try (BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile.toFile()))) {
        writer.write("You've been pwned.");
      }

      DefaultSAMLv2Service service = new DefaultSAMLv2Service();
      byte[] xml = Files.readAllBytes(Paths.get("src/test/xml/authn-request-external-dtd.xml"));

      // Set the filename in the XML
      String xmlString = new String(xml);
      xmlString = xmlString.replace("{{tempFile}}", tempFile.toFile().getAbsolutePath());
      xml = xmlString.getBytes(StandardCharsets.UTF_8);

      String deflated = SAMLTools.deflateAndEncode(xml);
      String queryString = "SAMLRequest=" + URLEncoder.encode(deflated, StandardCharsets.UTF_8);
      AuthenticationRequest request = service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper());
      fail("Expected an exception because we are declaring a DOCTYPE. The issuer is now set to [" + request.issuer + "] which is not good.");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Unable to parse SAML v2.0 document.");
      assertEquals(e.getCause().getClass().getCanonicalName(), "org.xml.sax.SAXParseException");
      assertEquals(e.getCause().getMessage(), "DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.");
    } finally {
      if (tempFile != null) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  @Test(dataProvider = "bindings")
  public void parseRequest_forceAuthn(Binding binding) throws Exception {
    byte[] bytes = Files.readAllBytes(Paths.get("src/test/xml/authn-request-forceAuthn.xml"));

    String encodedXML = binding == Binding.HTTP_Redirect
        ? SAMLTools.deflateAndEncode(bytes)
        : SAMLTools.encode(bytes);

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationRequest request = binding == Binding.HTTP_Redirect
        ? service.parseRequestRedirectBinding("SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8), authRequest -> new TestRedirectBindingSignatureHelper())
        : service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper());

    assertEquals(request.id, "_809707f0030a5d00620c9d9df97f627afe9dcc24");
    assertEquals(request.issuer, "http://sp.example.com/demo1/metadata.php");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
    assertEquals(request.forceAuthn, Boolean.TRUE);
  }

  @Test
  public void parseRequest_hasDocType() throws Exception {
    // Has DOCTYPE, fail. No DOCTYPE for you!
    try {
      DefaultSAMLv2Service service = new DefaultSAMLv2Service();
      byte[] xml = Files.readAllBytes(Paths.get("src/test/xml/authn-request-has-doctype.xml"));
      String deflated = SAMLTools.deflateAndEncode(xml);
      String queryString = "SAMLRequest=" + URLEncoder.encode(deflated, StandardCharsets.UTF_8);
      service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper());
      fail("expected an exception because we are declaring a DOCTYPE");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Unable to parse SAML v2.0 document.");
      assertEquals(e.getCause().getClass().getCanonicalName(), "org.xml.sax.SAXParseException");
      assertEquals(e.getCause().getMessage(), "DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.");
    }
  }

  @Test(dataProvider = "maxLineLength")
  public void parseRequest_includeLineReturns(int maxLineLength) throws Exception {
    String xml = new String(Files.readAllBytes(Paths.get("src/test/xml/authn-request-control.xml")));
    String encodedXML = new String(Files.readAllBytes(Paths.get("src/test/xml/deflated/authn-request-control.txt")));

    // Response has line returns, we've seen a customer that has line returns at 76
    List<String> lines = new ArrayList<>();
    for (int i = 0; i < encodedXML.length(); ) {
      lines.add(encodedXML.substring(i, Math.min(i + maxLineLength, encodedXML.length())));
      i = i + maxLineLength;
    }

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    String withLineReturns = String.join("\n", lines);
    String queryString = "SAMLRequest=" + URLEncoder.encode(withLineReturns, StandardCharsets.UTF_8);
    AuthenticationRequest request = service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper());

    assertEquals(request.id, "_809707f0030a5d00620c9d9df97f627afe9dcc24");
    assertEquals(request.issuer, "http://sp.example.com/demo1/metadata.php");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
    assertEquals(request.xml.replace("\r\n", "\n"), xml.replace("\r\n", "\n"));
  }

  @Test(dataProvider = "bindings")
  public void parseRequest_noNameIdPolicy(Binding binding) throws Exception {
    String xml = new String(Files.readAllBytes(Paths.get("src/test/xml/authn-request-noNameIdPolicy.xml")));
    String encodedXML = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/deflated/authn-request-noNameIdPolicy.txt")
        : Paths.get("src/test/xml/encoded/authn-request-noNameIdPolicy.txt")));

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationRequest request = binding == Binding.HTTP_Redirect
        ? service.parseRequestRedirectBinding("SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8), authRequest -> new TestRedirectBindingSignatureHelper())
        : service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper());

    // No Name Policy present in the request, we will default to Email
    assertEquals(request.id, "id_4c6e5aa3");
    assertEquals(request.issuer, "https://medallia.com/sso/mlg");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
    assertEquals(request.xml.replace("\r\n", "\n"), xml.replace("\r\n", "\n"));
  }

  @Test(dataProvider = "bindings")
  public void parseRequest_verifySignature(Binding binding) throws Exception {
    String xml = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/authn-request-redirect-signed.xml")
        : Paths.get("src/test/xml/authn-request-post-signed.xml")));
    String relayState = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/relay-state/authn-request-redirect.txt")
        : Paths.get("src/test/xml/relay-state/authn-request-post.txt")));
    String encodedXML = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/deflated/authn-request-signed.txt")
        : Paths.get("src/test/xml/encoded/authn-request-signed.txt")));
    String signature = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/signature/authn-request-redirect.txt")
        : Paths.get("src/test/xml/signature/authn-request-post.txt")));
    PublicKey publicKey = KeyFactory.getInstance("RSA")
                                    .generatePublic(
                                        new X509EncodedKeySpec(
                                            Base64.getMimeDecoder()
                                                  .decode(
                                                      Files.readAllBytes(binding == Binding.HTTP_Redirect
                                                          ? Paths.get("src/test/xml/public-key/authn-request-redirect.txt")
                                                          : Paths.get("src/test/xml/public-key/authn-request-post.txt"))

                                                  )));

    // For HTTP Redirect bindings
    String queryString = "SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8) +
        "&RelayState=" + URLEncoder.encode(relayState, StandardCharsets.UTF_8) +
        "&SigAlg=" + URLEncoder.encode(Algorithm.RS256.uri, StandardCharsets.UTF_8) +
        "&Signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationRequest request = binding == Binding.HTTP_Redirect
        ? service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper(publicKey, true))
        : service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), true));

    assertEquals(request.id, binding == Binding.HTTP_Redirect ? "ID_025417c8-50c8-4916-bfe0-e05694f8cea7" : "ID_26d69170-fc73-4b62-8bb6-c72769216134");
    assertEquals(request.issuer, "http://localhost:8080/auth/realms/master");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
    assertEquals(request.xml.replace("\r\n", "\n"), xml.replace("\r\n", "\n"));
  }

  @Test(dataProvider = "bindings")
  public void parseRequest_verifySignature_badSignature(Binding binding) throws Exception {
    String relayState = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/relay-state/authn-request-redirect.txt")
        : Paths.get("src/test/xml/relay-state/authn-request-post.txt")));
    String encodedXML = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/deflated/authn-request-signed.txt")
        : Paths.get("src/test/xml/encoded/authn-request-signed-badSignature.txt")));
    PublicKey publicKey = KeyFactory.getInstance("RSA")
                                    .generatePublic(
                                        new X509EncodedKeySpec(
                                            Base64.getMimeDecoder()
                                                  .decode(
                                                      Files.readAllBytes(binding == Binding.HTTP_Redirect
                                                          ? Paths.get("src/test/xml/public-key/authn-request-redirect.txt")
                                                          : Paths.get("src/test/xml/public-key/authn-request-post.txt"))

                                                  )));

    try {
      DefaultSAMLv2Service service = new DefaultSAMLv2Service();
      if (binding == Binding.HTTP_Redirect) {
        String signature = new String(Files.readAllBytes(Paths.get("src/test/xml/signature/authn-request-redirect-bad.txt"))); // Not used for POST binding
        String queryString = "SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8) +
            "&RelayState=" + URLEncoder.encode(relayState, StandardCharsets.UTF_8) +
            "&SigAlg=" + URLEncoder.encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", StandardCharsets.UTF_8) +
            "&Signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);
        service.parseRequestRedirectBinding(queryString, request -> new TestRedirectBindingSignatureHelper(publicKey, true));
      } else {
        service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), true));
      }

      fail("Should have failed signature validation");
    } catch (SAMLException e) {
      // Should throw
      assertEquals(e.getMessage(), "Invalid SAML v2.0 operation. The signature is invalid.");
    }
  }

  @Test(dataProvider = "bindings")
  public void parseRequest_withNameIdPolicy(Binding binding) throws Exception {
    String xml = new String(Files.readAllBytes(Paths.get("src/test/xml/authn-request-control.xml")));
    String encodedXML = new String(Files.readAllBytes(binding == Binding.HTTP_Redirect
        ? Paths.get("src/test/xml/deflated/authn-request-control.txt")
        : Paths.get("src/test/xml/encoded/authn-request-control.txt")));

    // For Redirect Binding
    String queryString = "SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8);

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationRequest request = binding == Binding.HTTP_Redirect
        ? service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper())
        : service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper());

    assertEquals(request.acsURL, "http://sp.example.com/demo1/index.php?acs");
    assertEquals(request.id, "_809707f0030a5d00620c9d9df97f627afe9dcc24");
    assertEquals(request.issuer, "http://sp.example.com/demo1/metadata.php");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
    assertEquals(request.xml.replace("\r\n", "\n"), xml.replace("\r\n", "\n"));
  }

  @Test
  public void parseResponse() throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    PublicKey key;
    try (InputStream is = Files.newInputStream(Paths.get("src/test/certificates/certificate.cer"))) {
      Certificate cert = cf.generateCertificate(is);
      key = cert.getPublicKey();
    }

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, true, KeySelector.singletonKeySelector(key));

    assertEquals(response.destination, "https://local.fusionauth.io/oauth2/callback");
    assertTrue(response.issueInstant.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertEquals(response.issuer, "https://sts.windows.net/c2150111-3c44-4508-9f08-790cb4032a23/");
    assertEquals(response.status.code, ResponseStatus.Success);
    Assertion assertion = response.assertions.get(0);
    assertTrue(assertion.conditions.notBefore.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertTrue(ZonedDateTime.now(ZoneOffset.UTC).isAfter(assertion.conditions.notOnOrAfter));
    assertEquals(assertion.attributes.get("http://schemas.microsoft.com/identity/claims/displayname").get(0), "Brian Pontarelli");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").get(0), "Brian");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").get(0), "Pontarelli");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").get(0), "brian@inversoft.com");
    assertNotNull(assertion.subject.nameIDs);
    assertEquals(assertion.subject.nameIDs.size(), 1);
    assertEquals(assertion.subject.nameIDs.get(0).format, NameIDFormat.EmailAddress.toSAMLFormat());
  }

  @Test
  public void parseResponse_handleNilAttribute() throws Exception {
    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/deflated/example-response.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    assertEquals(response.destination, "http://sp.example.com/demo1/index.php?acs");
    assertEquals(response.issuer, "http://idp.example.com/metadata.php");
    assertEquals(response.status.code, ResponseStatus.Success);
    Assertion assertion = response.assertions.get(0);
    assertTrue(assertion.conditions.notBefore.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertEquals(assertion.attributes.get("uid").size(), 1);
    assertEquals(assertion.attributes.get("uid").get(0), "test");
    assertEquals(assertion.attributes.get("mail").size(), 1);
    assertEquals(assertion.attributes.get("mail").get(0), "test@example.com");
    assertEquals(assertion.attributes.get("eduPersonAffiliation").size(), 2);
    assertEquals(assertion.attributes.get("eduPersonAffiliation").get(0), "users");
    assertEquals(assertion.attributes.get("eduPersonAffiliation").get(1), "examplerole1");
    assertEquals(assertion.attributes.get("memberOf").size(), 1);
    assertEquals(assertion.attributes.get("memberOf").get(0), "");
    // Ensure we can handle
    //  <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true" xsi:type="xs:string"/>
    assertEquals(assertion.attributes.get("PersonImmutableID").size(), 1);
    assertNull(assertion.attributes.get("PersonImmutableID").get(0));
    assertNotNull(assertion.subject.nameIDs);
    assertEquals(assertion.subject.nameIDs.size(), 1);
    assertEquals(assertion.subject.nameIDs.get(0).format, NameIDFormat.Transient.toSAMLFormat());
    // Make sure our copy constructor handles nulls properly
    var copy = new Assertion(assertion);
    assertEquals(copy, assertion);
  }

  @Test(dataProvider = "maxLineLength")
  public void parseResponse_includeLineReturns(int maxLineLength) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    PublicKey key;
    try (InputStream is = Files.newInputStream(Paths.get("src/test/certificates/certificate.cer"))) {
      Certificate cert = cf.generateCertificate(is);
      key = cert.getPublicKey();
    }

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba);
    // Response has line returns, we've seen a customer that has line returns at 76
    List<String> lines = new ArrayList<>();
    for (int i = 0; i < encodedResponse.length(); ) {
      lines.add(encodedResponse.substring(i, Math.min(i + maxLineLength, encodedResponse.length())));
      i = i + maxLineLength;
    }

    String withLineReturns = String.join("\n", lines);

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(withLineReturns, true, KeySelector.singletonKeySelector(key));

    assertEquals(response.destination, "https://local.fusionauth.io/oauth2/callback");
    assertTrue(response.issueInstant.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertEquals(response.issuer, "https://sts.windows.net/c2150111-3c44-4508-9f08-790cb4032a23/");
    assertEquals(response.status.code, ResponseStatus.Success);
    Assertion assertion = response.assertions.get(0);
    assertTrue(assertion.conditions.notBefore.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertTrue(ZonedDateTime.now(ZoneOffset.UTC).isAfter(assertion.conditions.notOnOrAfter));
    assertEquals(assertion.attributes.get("http://schemas.microsoft.com/identity/claims/displayname").get(0), "Brian Pontarelli");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").get(0), "Brian");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").get(0), "Pontarelli");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").get(0), "brian@inversoft.com");
    assertNotNull(assertion.subject.nameIDs);
    assertEquals(assertion.subject.nameIDs.size(), 1);
    assertEquals(assertion.subject.nameIDs.get(0).format, NameIDFormat.EmailAddress.toSAMLFormat());
  }

  @Test
  public void parseResponse_multipleAssertions_ignoreSignature() throws Exception {
    // When signature verification is skipped, unsigned assertions and assertions with invalid signatures are included in the response.
    String responseXml = baseXml.replace("${assertions}", String.join("", List.of(assertionSigned, assertionUnsigned, encryptedSigned, encryptedUnsigned)));
    String encodedResponse = Base64.getMimeEncoder().encodeToString(responseXml.getBytes(StandardCharsets.UTF_8));

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    // Parse the response skipping signature verification
    AuthenticationResponse response = service.parseResponse(
        encodedResponse,
        false,
        // This is the wrong key to verify signatures, but we skip entirely.
        KeySelector.singletonKeySelector(encryptionKeyPair.getPublic()),
        false,
        encryptionKeyPair.getPrivate()
    );

    // All four assertions are included on the response
    assertEquals(response.assertions.size(), 4);
  }

  @Test
  public void parseResponse_multipleAssertions_verifySignature() throws Exception {
    // When signature verification is requested, unsigned assertions are excluded from the parsed response.
    String responseXml = baseXml.replace("${assertions}", String.join("", List.of(assertionSigned, assertionUnsigned, encryptedSigned, encryptedUnsigned)));
    String encodedResponse = Base64.getMimeEncoder().encodeToString(responseXml.getBytes(StandardCharsets.UTF_8));

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    // Parse the response as unencrypted with signature verification.
    AuthenticationResponse response = service.parseResponse(
        encodedResponse,
        true,
        KeySelector.singletonKeySelector(signingKeyPair.getPublic()),
        false,
        encryptionKeyPair.getPrivate()
    );
    // The response should only contain the signed plaintext and signed encrypted assertions.
    // - Unsigned assertions are excluded from the response.
    assertEquals(response.assertions.size(), 2);
    assertEquals(response.assertions.get(0).id, "_b839e63e-4673-43a8-b226-ef73676a70b1");
    assertEquals(response.assertions.get(1).id, "_604b9303-a5b0-411f-9b3a-5f525fe6887b");

    // Parse the response as encrypted with signature verification.
    response = service.parseResponse(
        encodedResponse,
        true,
        KeySelector.singletonKeySelector(signingKeyPair.getPublic()),
        true,
        encryptionKeyPair.getPrivate()
    );

    // The response should only contain the one signed encrypted assertion.
    // - Unsigned encrypted assertions are excluded from the response.
    // - Plaintext assertions are excluded from the response.
    assertEquals(response.assertions.size(), 1);
    assertEquals(response.assertions.get(0).id, "_604b9303-a5b0-411f-9b3a-5f525fe6887b");

    // Build another response containing only unsigned assertions
    responseXml = baseXml.replace("${assertions}", String.join("", List.of(assertionUnsigned, encryptedUnsigned)));
    encodedResponse = Base64.getMimeEncoder().encodeToString(responseXml.getBytes(StandardCharsets.UTF_8));

    // Parse the response as plaintext with signature verification. Expect an exception due to no signed elements.
    try {
      service.parseResponse(
          encodedResponse,
          true,
          KeySelector.singletonKeySelector(signingKeyPair.getPublic()),
          false,
          encryptionKeyPair.getPrivate()
      );
      fail("Expected SignatureNotFoundException");
    } catch (SignatureNotFoundException e) {
      assertEquals(e.getMessage(), "Invalid SAML v2.0 operation. The signature is missing from the XML but is required.");
    }
  }

  @Test
  public void parseResponse_requireEncryptedAssertion_unencrypted() throws Exception {
    // Test that a response containing an unencrypted assertion fails when encryption is required.
    // Load response from file
    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba, StandardCharsets.UTF_8);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    // Require assertion encryption, but provide an assertion without encryption.
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null, true, null);
    // Skipped parsing the unencrypted assertion. The assertion was not included in the response.
    assertTrue(response.assertions.isEmpty());
  }

  @Test
  public void parseResponse_signatureCheck_badSignature() throws Exception {
    // Test that an exception is thrown when there is a bad signature in the document.
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();

    // [1] Invalid Signature on Assertion
    String responseXml = baseXml.replace("${assertions}", assertionSigned);
    String encodedResponse = Base64.getMimeEncoder().encodeToString(responseXml.getBytes(StandardCharsets.UTF_8));
    try {
      service.parseResponse(
          encodedResponse,
          true,
          // This is the wrong key to validate the Signature on the Assertion
          KeySelector.singletonKeySelector(encryptionKeyPair.getPublic())
      );
      fail("Expected SAMLException");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Invalid SAML v2.0 operation. The signature is invalid.");
    }

    // [2] Invalid Signature on EncryptedAssertion
    responseXml = baseXml.replace("${assertions}", encryptedSigned);
    encodedResponse = Base64.getMimeEncoder().encodeToString(responseXml.getBytes(StandardCharsets.UTF_8));
    try {
      service.parseResponse(
          encodedResponse,
          true,
          // This is the wrong key to validate the Signature on the EncryptedAssertion
          KeySelector.singletonKeySelector(encryptionKeyPair.getPublic()),
          true,
          encryptionKeyPair.getPrivate()
      );
      fail("Expected SAMLException");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Invalid SAML v2.0 operation. The signature is invalid.");
    }

    // [3] Invalid Signature on Response
    responseXml = baseXml.replace("${assertions}", assertionUnsigned);
    encodedResponse = Base64.getMimeEncoder().encodeToString(responseXml.getBytes(StandardCharsets.UTF_8));
    // Parse the unsigned Response
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);
    // Build a new Response with a signature at the Response level
    encodedResponse = service.buildAuthnResponse(response, true, signingKeyPair.getPrivate(), CertificateTools.fromKeyPair(signingKeyPair, Algorithm.RS256, "FooBar"), Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, SignatureLocation.Response, false);
    try {
      service.parseResponse(
          encodedResponse,
          true,
          // This is the wrong key to validate the Signature on the Response
          KeySelector.singletonKeySelector(encryptionKeyPair.getPublic())
      );
      fail("Expected SAMLException");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Invalid SAML v2.0 operation. The signature is invalid.");
    }
  }

  @Test
  public void parseResponse_signatureCheck_missing() throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    PublicKey key;
    try (InputStream is = Files.newInputStream(Paths.get("src/test/certificates/certificate.cer"))) {
      Certificate cert = cf.generateCertificate(is);
      key = cert.getPublicKey();
    }

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse-signatureRemoved.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    try {
      service.parseResponse(encodedResponse, true, KeySelector.singletonKeySelector(key));
      fail("Should have thrown an exception");
    } catch (SAMLException e) {
      // Should throw
      assertEquals(e.getMessage(), "Invalid SAML v2.0 operation. The signature is missing from the XML but is required.");
    }
  }

  @Test
  public void parseResponse_signatureCheck_missingEncrypted() throws Exception {
    // Test that a response containing an encrypted assertion fails when an expected signature is missing.
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair encryptionKeyPair = kpg.generateKeyPair();

    // Load response from file
    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba, StandardCharsets.UTF_8);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    // Build an encrypted AuthenticationResponse without a signature
    String encodedXML = service.buildAuthnResponse(
        response,
        false,
        null,
        null,
        Algorithm.RS256,
        CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
        SignatureLocation.Response,
        false,
        true,
        EncryptionAlgorithm.AES128GCM,
        KeyLocation.Child,
        KeyTransportAlgorithm.RSA_OAEP,
        CertificateTools.fromKeyPair(encryptionKeyPair, Algorithm.RS256, "FooBar"),
        DigestAlgorithm.SHA256,
        MaskGenerationFunction.MGF1_SHA1
    );

    try {
      // Attempt to parse the encrypted response. Expect an exception for missing signature
      service.parseResponse(
          encodedXML,
          true, null,
          true, encryptionKeyPair.getPrivate()
      );
      fail("Should have thrown an exception");
    } catch (SAMLException e) {
      // Should throw
      assertEquals(e.getMessage(), "Invalid SAML v2.0 operation. The signature is missing from the XML but is required.");
    }
  }

  @Test(dataProvider = "bindings")
  public void parse_LogoutRequest(Binding binding) throws Exception {
    byte[] bytes = binding == Binding.HTTP_Redirect
        ? Files.readAllBytes(Paths.get("src/test/xml/logout-request.xml"))
        : Files.readAllBytes(Paths.get("src/test/xml/logout-request-embedded-signature.xml"));

    String encodedXML = binding == Binding.HTTP_Redirect
        ? SAMLTools.deflateAndEncode(bytes)
        : SAMLTools.encode(bytes);

    X509Certificate certificate;
    String redirectSignature = Files.readString(Paths.get("src/test/xml/signature/logout-request.txt"));
    String x509encoded = "MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==";
    try (InputStream is = new ByteArrayInputStream(Base64.getMimeDecoder().decode(x509encoded))) {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      certificate = (X509Certificate) factory.generateCertificate(is);
    }

    assertNotNull(certificate);
    PublicKey publicKey = certificate.getPublicKey();

    String queryString = "SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8) +
        "&RelayState=" + URLEncoder.encode("http://sp.example.com/relaystate", StandardCharsets.UTF_8) +
        "&SigAlg=" + URLEncoder.encode(Algorithm.RS1.uri, StandardCharsets.UTF_8) +
        "&Signature=" + URLEncoder.encode(redirectSignature, StandardCharsets.UTF_8);

    // Testing purposes, signatures can't be verified currently, TBD if this is a bug or just invalid signatures.
    // - Disable signature verification for now.
    boolean verifySignature = false;
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    LogoutRequest request = binding == Binding.HTTP_Redirect
        ? service.parseLogoutRequestRedirectBinding(queryString, logoutRequest -> new TestRedirectBindingSignatureHelper(publicKey, verifySignature))
        : service.parseLogoutRequestPostBinding(encodedXML, logoutRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), verifySignature));

    assertEquals(request.id, binding == Binding.HTTP_Redirect
        ? "ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d"
        : "pfxd4d369e8-9ea1-780c-aff8-a1d11a9862a1");
    assertEquals(request.issuer, "http://sp.example.com/demo1/metadata.php");
    assertEquals(request.nameIdFormat, NameIDFormat.Transient.toSAMLFormat());
    assertEquals(request.version, "2.0");
    String expectedXML = new String(bytes, StandardCharsets.UTF_8);
    assertEquals(request.xml.replace("\r\n", "\n"), expectedXML.replace("\r\n", "\n"));
  }

  @Test(dataProvider = "bindings")
  public void parse_LogoutResponse(Binding binding) throws Exception {
    byte[] bytes = binding == Binding.HTTP_Redirect
        ? Files.readAllBytes(Paths.get("src/test/xml/logout-response.xml"))
        : Files.readAllBytes(Paths.get("src/test/xml/logout-response-embedded-signature.xml"));

    String encodedXML = binding == Binding.HTTP_Redirect
        ? SAMLTools.deflateAndEncode(bytes)
        : SAMLTools.encode(bytes);

    X509Certificate certificate;
    String redirectSignature = Files.readString(Paths.get("src/test/xml/signature/logout-response.txt"));
    String x509encoded = "MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==";
    try (InputStream is = new ByteArrayInputStream(Base64.getMimeDecoder().decode(x509encoded))) {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      certificate = (X509Certificate) factory.generateCertificate(is);
    }

    assertNotNull(certificate);
    PublicKey publicKey = certificate.getPublicKey();

    // For Redirect Binding
    String queryString = "SAMLRequest=" + URLEncoder.encode(encodedXML, StandardCharsets.UTF_8) +
        "&RelayState=" + URLEncoder.encode("http://sp.example.com/relaystate", StandardCharsets.UTF_8) +
        "&SigAlg=" + URLEncoder.encode(Algorithm.RS1.uri, StandardCharsets.UTF_8) +
        "&Signature=" + URLEncoder.encode(redirectSignature, StandardCharsets.UTF_8);

    // Testing purposes, signatures can't be verified currently, TBD if this is a bug or just invalid signatures.
    // - Disable signature verification for now.
    boolean verifySignature = false;
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    LogoutResponse response = binding == Binding.HTTP_Redirect
        ? service.parseLogoutResponseRedirectBinding(queryString, logoutRequest -> new TestRedirectBindingSignatureHelper(publicKey, verifySignature))
        : service.parseLogoutResponsePostBinding(encodedXML, logoutRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), verifySignature));

    assertEquals(response.id, binding == Binding.HTTP_Redirect
        ? "_6c3737282f007720e736f0f4028feed8cb9b40291c"
        : "pfxe335499f-e73b-80bd-60c4-1628984aed4f");
    assertEquals(response.issuer, "http://idp.example.com/metadata.php");
    assertEquals(response.version, "2.0");
    assertNull(response.inResponseTo);
    assertNull(response.sessionIndex);
    String expectedXML = new String(bytes, StandardCharsets.UTF_8);
    assertEquals(response.xml.replace("\r\n", "\n"), expectedXML.replace("\r\n", "\n"));
  }

  @Test(dataProvider = "bindings")
  public void roundTripAuthnRequest(Binding binding) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String queryString;
    if (binding == Binding.HTTP_Redirect) {
      queryString = service.buildRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.RS256);
    } else {
      X509Certificate cert = generateX509Certificate(kp, "SHA256withRSA");
      queryString = service.buildPostAuthnRequest(request, true, kp.getPrivate(), cert, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    }

    if (binding == Binding.HTTP_Redirect) {
      request = service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper(kp.getPublic(), true));
    } else {
      request = service.parseRequestPostBinding(queryString, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(kp.getPublic()), true));
    }

    // Assert the parsed request
    assertEquals(request.id, "foobarbaz");
    assertEquals(request.issuer, "https://local.fusionauth.io");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
  }

  @Test(dataProvider = "bindings")
  public void roundTripAuthnRequest_ECDSA(Binding binding) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(256);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String queryString;
    if (binding == Binding.HTTP_Redirect) {
      queryString = service.buildRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.ES256);
    } else {
      X509Certificate cert = generateX509Certificate(kp, "SHA256withECDSA");
      queryString = service.buildPostAuthnRequest(request, true, kp.getPrivate(), cert, Algorithm.ES256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    }

    if (binding == Binding.HTTP_Redirect) {
      request = service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper(kp.getPublic(), true));
    } else {
      request = service.parseRequestPostBinding(queryString, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(kp.getPublic()), true));
    }

    // Assert the parsed request
    assertEquals(request.id, "foobarbaz");
    assertEquals(request.issuer, "https://local.fusionauth.io");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
  }

  @Test(dataProvider = "assertionEncryption")
  public void roundTripResponseEncryptedAssertion(EncryptionAlgorithm encryptionAlgorithm, KeyLocation keyLocation,
                                                  KeyTransportAlgorithm transportAlgorithm, DigestAlgorithm digest,
                                                  MaskGenerationFunction mgf)
      throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair signingKeyPair = kpg.generateKeyPair();
    KeyPair encryptionKeyPair = kpg.generateKeyPair();

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba, StandardCharsets.UTF_8);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    // Build an encrypted AuthenticationResponse with the signature at the Response level
    String encodedXML = service.buildAuthnResponse(
        response,
        true,
        signingKeyPair.getPrivate(),
        CertificateTools.fromKeyPair(signingKeyPair, Algorithm.RS256, "FooBar"),
        Algorithm.RS256,
        CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
        SignatureLocation.Response,
        true,
        true,
        encryptionAlgorithm,
        keyLocation,
        transportAlgorithm,
        CertificateTools.fromKeyPair(encryptionKeyPair, Algorithm.RS256, "FooBar"),
        digest,
        mgf
    );

    // Parse the encrypted response
    AuthenticationResponse parsedResponse = service.parseResponse(
        encodedXML,
        true, KeySelector.singletonKeySelector(signingKeyPair.getPublic()),
        true, encryptionKeyPair.getPrivate()
    );

    // Verify the parsed encrypted response matches the original pulled from file
    assertEquals(parsedResponse, response);

    // Build an encrypted AuthenticationResponse with the inside the encrypted Assertion
    encodedXML = service.buildAuthnResponse(
        response,
        true,
        signingKeyPair.getPrivate(),
        CertificateTools.fromKeyPair(signingKeyPair, Algorithm.RS256, "FooBar"),
        Algorithm.RS256,
        CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
        SignatureLocation.Assertion,
        true,
        true,
        encryptionAlgorithm,
        keyLocation,
        transportAlgorithm,
        CertificateTools.fromKeyPair(encryptionKeyPair, Algorithm.RS256, "FooBar"),
        digest,
        mgf
    );

    // Parse the encrypted response
    parsedResponse = service.parseResponse(
        encodedXML,
        true, KeySelector.singletonKeySelector(signingKeyPair.getPublic()),
        true, encryptionKeyPair.getPrivate()
    );

    // Verify the parsed encrypted response matches the original pulled from file
    assertEquals(parsedResponse, response);
  }

  @Test(dataProvider = "signatureLocation")
  public void roundTripResponseFailedRequestSignedAssertion(SignatureLocation signatureLocation,
                                                            boolean includeKeyInfoInResponse)
      throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse-authnFailed.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    String encodedXML = service.buildAuthnResponse(response, true, kp.getPrivate(), CertificateTools.fromKeyPair(kp, Algorithm.RS256, "FooBar"), Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, signatureLocation, includeKeyInfoInResponse);
    response = service.parseResponse(encodedXML, true, new TestKeySelector(kp.getPublic()));

    // Since the request is failed there should always be a signature in the response because there is no assertion present
    Document document = parseDocument(encodedXML);
    Node signature = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
    assertEquals(signature.getPreviousSibling().getLocalName(), "Issuer");
    assertEquals(signature.getNextSibling().getLocalName(), "Status");
    assertEquals(signature.getParentNode().getLocalName(), "Response");

    assertEquals(response.destination, "https://local.fusionauth.io/samlv2/acs");
    assertTrue(response.issueInstant.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertEquals(response.issuer, "https://acme.com/saml/idp");
    assertEquals(response.status.code, ResponseStatus.AuthenticationFailed);
  }

  @Test
  public void authnInstant() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    ZonedDateTime expectedAuthnInstant = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1);
    response.authnInstant = expectedAuthnInstant;

    String encodedXML = service.buildAuthnResponse(response, true, kp.getPrivate(), CertificateTools.fromKeyPair(kp, Algorithm.RS256, "FooBar"), Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, SignatureLocation.Response, true);
    AuthenticationResponse builtResponse = service.parseResponse(encodedXML, true, new TestKeySelector(kp.getPublic()));

    assertEquals(builtResponse.status.code, ResponseStatus.Success);
    // Expected to be the value we set, convert back and forth to sync up the formats
    assertEquals(builtResponse.authnInstant, SAMLTools.toZonedDateTime(SAMLTools.toXMLGregorianCalendar(expectedAuthnInstant)));
    assertTrue(builtResponse.issueInstant.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));

    response.authnInstant = null;
    response.issueInstant = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(2);
    encodedXML = service.buildAuthnResponse(response, true, kp.getPrivate(), CertificateTools.fromKeyPair(kp, Algorithm.RS256, "FooBar"), Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, SignatureLocation.Response, true);
    builtResponse = service.parseResponse(encodedXML, true, new TestKeySelector(kp.getPublic()));

    assertEquals(builtResponse.status.code, ResponseStatus.Success);
    assertEquals(builtResponse.authnInstant, builtResponse.issueInstant);
    assertTrue(builtResponse.issueInstant.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
  }

  @Test(dataProvider = "signatureLocation")
  public void roundTripResponseSignedAssertion(SignatureLocation signatureLocation, boolean includeKeyInfoInResponse)
      throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    ZonedDateTime expectedAuthnInstant = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1);
    response.authnInstant = expectedAuthnInstant;
    String encodedXML = service.buildAuthnResponse(response, true, kp.getPrivate(), CertificateTools.fromKeyPair(kp, Algorithm.RS256, "FooBar"), Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, signatureLocation, includeKeyInfoInResponse);
    // System.out.println(new String(Base64.getMimeDecoder().decode(encodedXML)));
    response = service.parseResponse(encodedXML, true, new TestKeySelector(kp.getPublic()));

    // Assert the signature is in the correct location based upon the signature option provided.
    Document document = parseDocument(encodedXML);
    Node signature = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
    if (signatureLocation == SignatureLocation.Assertion) {
      // Previous sibling is expected to be the Issuer, and the next sibling should be Subject.
      assertEquals(signature.getPreviousSibling().getLocalName(), "Issuer");
      assertEquals(signature.getNextSibling().getLocalName(), "Subject");
      // The parent node should be the assertion.
      assertEquals(signature.getParentNode().getLocalName(), "Assertion");
    } else {
      // The Signature should be a child of the Response, and come immediately following the Issuer.
      assertEquals(signature.getParentNode().getLocalName(), "Response");
      assertEquals(signature.getPreviousSibling().getLocalName(), "Issuer");
    }

    assertEquals(response.authnInstant, SAMLTools.toZonedDateTime(SAMLTools.toXMLGregorianCalendar(expectedAuthnInstant)));
    assertEquals(response.destination, "https://local.fusionauth.io/oauth2/callback");
    assertTrue(response.issueInstant.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertEquals(response.issuer, "https://sts.windows.net/c2150111-3c44-4508-9f08-790cb4032a23/");
    assertEquals(response.status.code, ResponseStatus.Success);
    Assertion assertion = response.assertions.get(0);
    assertTrue(assertion.conditions.notBefore.isBefore(ZonedDateTime.now(ZoneOffset.UTC)));
    assertTrue(ZonedDateTime.now(ZoneOffset.UTC).isAfter(assertion.conditions.notOnOrAfter));
    assertEquals(assertion.attributes.get("http://schemas.microsoft.com/identity/claims/displayname").get(0), "Brian Pontarelli");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").get(0), "Brian");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").get(0), "Pontarelli");
    assertEquals(assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").get(0), "brian@inversoft.com");
    assertNotNull(assertion.subject.nameIDs);
    assertEquals(assertion.subject.nameIDs.size(), 1);
    assertEquals(assertion.subject.nameIDs.get(0).format, NameIDFormat.EmailAddress.toSAMLFormat());
  }

  @DataProvider(name = "signatureLocation")
  public Object[][] signatureLocation() {
    return new Object[][]{
        {SignatureLocation.Assertion, true},
        {SignatureLocation.Assertion, false},
        {SignatureLocation.Response, true},
        {SignatureLocation.Response, false}
    };
  }

  @Test
  public void unmarshalPerformance() throws Exception {
    String encodedRequest = SAMLTools.encode(Files.readAllBytes(Paths.get("src/test/xml/authn-request-control.xml")));

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    long iterations = 5_000;
    long start = System.currentTimeMillis();
    for (int i = 0; i < iterations; i++) {
      service.parseRequestPostBinding(encodedRequest, authRequest -> new TestPostBindingSignatureHelper());
    }

    long total = System.currentTimeMillis() - start;
    double avg = total / iterations;

    // Ensure this is reasonably fast
    assertTrue(avg < 1.0, "Not fast enough!\nIterations: " + iterations + ", total time: " + total + " ms, avg: " + avg + " ms\n");
  }

  @Test
  public void variousURLEncoding_SignatureVerification() throws Exception {
    // Use case: URL encoding is not canonical, so when we calculate the signature we cannot assume if we URL encode a value it will be equal to the way it was URL encoded when the signature was first generated.
    // - Try using different URl encoding to ensure we can calculate the signature correctly.
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    MockDefaultSAMLv2Service service = new MockDefaultSAMLv2Service();

    // Use our own URL encoding, expected to work.
    String queryString = service.buildRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.RS256);
    request = service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper(kp.getPublic(), true));

    // Assert the parsed request
    assertEquals(request.id, "foobarbaz");
    assertEquals(request.issuer, "https://local.fusionauth.io");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");

    // Rebuild the query string using lower case hex
    service.lowerCaseURLEncoding = true;
    queryString = service.buildRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.RS256);
    request = service.parseRequestRedirectBinding(queryString, authRequest -> new TestRedirectBindingSignatureHelper(kp.getPublic(), true));

    // Assert the parsed request
    assertEquals(request.id, "foobarbaz");
    assertEquals(request.issuer, "https://local.fusionauth.io");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress.toSAMLFormat());
    assertEquals(request.version, "2.0");
  }

  private X509Certificate generateX509Certificate(KeyPair keyPair, String algorithm) throws IllegalArgumentException {
    try {
      ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
      X509CertInfo certInfo = new X509CertInfo();
      CertificateX509Key certKey = new CertificateX509Key(keyPair.getPublic());
      certInfo.set(X509CertInfo.KEY, certKey);
      certInfo.set(X509CertInfo.VERSION, new CertificateVersion(1));
      certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(new AlgorithmId(ObjectIdentifier.of(KnownOIDs.SHA256withRSA))));
      certInfo.set(X509CertInfo.ISSUER, new X500Name("CN=FusionAuth"));
      certInfo.set(X509CertInfo.SUBJECT, new X500Name("CN=FusionAuth"));
      certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(Date.from(now.toInstant()), Date.from(now.plusYears(10).toInstant())));
      certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16)));

      X509CertImpl impl = new X509CertImpl(certInfo);
      impl.sign(keyPair.getPrivate(), algorithm);
      return impl;
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  private void loadAssertionTemplates() throws IOException {
    baseXml = Files.readString(Paths.get("src/test/xml/assertion/response-template.xml.txt"));
    assertionSigned = Files.readString(Paths.get("src/test/xml/assertion/assertion-signed.xml.txt"));
    assertionUnsigned = Files.readString(Paths.get("src/test/xml/assertion/assertion-unsigned.xml.txt"));
    encryptedSigned = Files.readString(Paths.get("src/test/xml/assertion/encrypted-signed.xml.txt"));
    encryptedUnsigned = Files.readString(Paths.get("src/test/xml/assertion/encrypted-unsigned.xml.txt"));

  }

  private void loadKeys() throws Exception {
    try (
        InputStream isSigCert = Files.newInputStream(Paths.get("src/test/certificates/signature-certificate.pem"));
        InputStream isSigKey = Files.newInputStream(Paths.get("src/test/certificates/signature-private-pkcs8.der"));
        InputStream isEncCert = Files.newInputStream(Paths.get("src/test/certificates/encryption-certificate.pem"));
        InputStream isEncKey = Files.newInputStream(Paths.get("src/test/certificates/encryption-private-pkcs8.der"))
    ) {
      KeyFactory kf = KeyFactory.getInstance("RSA");
      PKCS8EncodedKeySpec sigKeySpec = new PKCS8EncodedKeySpec(isSigKey.readAllBytes());
      PrivateKey sigKey = kf.generatePrivate(sigKeySpec);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      Certificate sigCert = cf.generateCertificate(isSigCert);
      signingKeyPair = new KeyPair(sigCert.getPublicKey(), sigKey);

      PKCS8EncodedKeySpec encKeySpec = new PKCS8EncodedKeySpec(isEncKey.readAllBytes());
      PrivateKey encKey = kf.generatePrivate(encKeySpec);
      cf = CertificateFactory.getInstance("X.509");
      Certificate encCert = cf.generateCertificate(isEncCert);
      encryptionKeyPair = new KeyPair(encCert.getPublicKey(), encKey);
    }
  }

  private Document parseDocument(String encoded) throws ParserConfigurationException {
    byte[] bytes = Base64.getMimeDecoder().decode(encoded);
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setExpandEntityReferences(false);
    documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    documentBuilderFactory.setNamespaceAware(true);
    try {
      DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
      return builder.parse(new ByteArrayInputStream(bytes));
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static class MockDefaultSAMLv2Service extends DefaultSAMLv2Service {
    public boolean lowerCaseURLEncoding = false;

    @Override
    protected String urlEncode(String s) {
      if (lowerCaseURLEncoding) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8)
                         .replace("%2B", "%2b")
                         .replace("%2F", "%2f")
                         .replace("%3A", "%3a")
                         .replace("%3D", "%3d");
      } else {
        return super.urlEncode(s);
      }
    }
  }
}
