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
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.zip.Inflater;

import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.Binding;
import io.fusionauth.samlv2.domain.MetaData;
import io.fusionauth.samlv2.domain.MetaData.IDPMetaData;
import io.fusionauth.samlv2.domain.MetaData.SPMetaData;
import io.fusionauth.samlv2.domain.NameIDFormat;
import io.fusionauth.samlv2.domain.ResponseStatus;
import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.domain.SignatureLocation;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
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
  @BeforeClass
  public void beforeClass() {
    System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
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
    System.out.println(xml);
    assertTrue(xml.contains("_" + metaData.id));
    assertTrue(xml.contains(metaData.entityId));
    assertTrue(xml.contains(metaData.idp.postBindingSignInEndpoints.get(0)));
    assertTrue(xml.contains(metaData.idp.postBindingLogoutEndpoints.get(0)));
    assertTrue(xml.contains(metaData.idp.redirectBindingLogoutEndpoints.get(0)));
    assertTrue(xml.contains(metaData.idp.redirectBindingLogoutEndpoints.get(0)));
    assertTrue(xml.contains("<ns2:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"));

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

  @Test
  public void buildRedirectAuthnRequest() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String parameters = service.buildRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.RS256);
    System.out.println(parameters);
//    assertEquals(parameters, "SAMLRequest=eJx9kNtOwzAMhl8lMtdt0rQ7RU2niQlpEiDEBvdZ63WVsmQkKWVvTzZON8Cl7c%2BW%2F6%2Bcvx00eUXnO2skZCkDgqa2TWdaCU%2Bbm2QKxAdlGqWtQQnGwrwqjc%2BF6sPePOJLjz5sTkck8ZLxIo4k9M4Iq3wXS3VAL0It1ou7W8FTJo7OBltbDR8L%2F8PKe3Qh%2Fgbf57mEfQhHQekwDOmQp9a1lDPGKJvRCDW%2Ba69%2B8OIPPKOsOOMxbaRXSwmIBZ%2Fkiifb0bhOijzLk%2BlEYTKabTnjE9bsxuNIet%2FjypydBAlAnr%2FcxXehKi9jV4UoJSokGc9L%2Btm7WLuPEVfLB6u7%2BkQWWtvh2qEK0exOaY9Aq5L%2BZrd6BwQejFI%3D&RelayState=Relay-State-String&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=MCwCFCZDBcWxZD65RY0AR8K4WhNzs0tZAhRQFyc80lMy7yTl9a8UQMSST4wioA%3D%3D");

    // Unwind the request and assert its components
    int start = parameters.indexOf("=");
    int end = parameters.indexOf("&");
    String encodedRequest = URLDecoder.decode(parameters.substring(start + 1, end), "UTF-8");
    byte[] bytes = Base64.getMimeDecoder().decode(encodedRequest);

    // Decode and inflate the result and ensure it is equal to the raw and can be unmarshalled
    byte[] inflatedBytes = new byte[4096];
    Inflater inflater = new Inflater(true);
    inflater.setInput(bytes);
    int length = inflater.inflate(inflatedBytes);
    JAXBContext context = JAXBContext.newInstance(AuthnRequestType.class);
    Unmarshaller unmarshaller = context.createUnmarshaller();

    JAXBElement<AuthnRequestType> fromEncoded = (JAXBElement<AuthnRequestType>) unmarshaller.unmarshal(new ByteArrayInputStream(inflatedBytes, 0, length));
    assertEquals(fromEncoded.getValue().getID(), "foobarbaz");
    assertEquals(fromEncoded.getValue().getIssuer().getValue(), "https://local.fusionauth.io");
    assertEquals(fromEncoded.getValue().getVersion(), "2.0");
    assertFalse(fromEncoded.getValue().getNameIDPolicy().isAllowCreate());

    // Unwind the RelayState
    start = parameters.indexOf("RelayState=");
    end = parameters.indexOf("&", start);
    String relayState = parameters.substring(start + "RelayState=".length(), end);
    assertEquals(relayState, "Relay-State-String");

    // Unwind the SigAlg
    start = parameters.indexOf("SigAlg=");
    end = parameters.indexOf("&", start);
    String sigAlg = URLDecoder.decode(parameters.substring(start + "SigAlg=".length(), end), "UTF-8");
    assertEquals(sigAlg, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
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
    System.out.println(xml);
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

    String withLineReturns = String.join("\n", lines);

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationRequest request = service.parseRequestRedirectBinding(withLineReturns, null, authRequest -> new TestRedirectBindingSignatureHelper());

    assertEquals(request.id, "_809707f0030a5d00620c9d9df97f627afe9dcc24");
    assertEquals(request.issuer, "http://sp.example.com/demo1/metadata.php");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress);
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
        ? service.parseRequestRedirectBinding(encodedXML, null, authRequest -> new TestRedirectBindingSignatureHelper())
        : service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper());

    // No Name Policy present in the request, we will default to Email
    assertEquals(request.id, "id_4c6e5aa3");
    assertEquals(request.issuer, "https://medallia.com/sso/mlg");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress);
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
                                            Base64.getDecoder()
                                                  .decode(
                                                      Files.readAllBytes(binding == Binding.HTTP_Redirect
                                                          ? Paths.get("src/test/xml/public-key/authn-request-redirect.txt")
                                                          : Paths.get("src/test/xml/public-key/authn-request-post.txt"))

                                                  )));

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationRequest request = binding == Binding.HTTP_Redirect
        ? service.parseRequestRedirectBinding(encodedXML, relayState, authRequest -> new TestRedirectBindingSignatureHelper(Algorithm.RS256, publicKey, signature, true))
        : service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), true));

    assertEquals(request.id, binding == Binding.HTTP_Redirect ? "ID_025417c8-50c8-4916-bfe0-e05694f8cea7" : "ID_26d69170-fc73-4b62-8bb6-c72769216134");
    assertEquals(request.issuer, "http://localhost:8080/auth/realms/master");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress);
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
    String signature = new String(Files.readAllBytes(Paths.get("src/test/xml/signature/authn-request-redirect-bad.txt"))); // Not used for POST binding
    PublicKey publicKey = KeyFactory.getInstance("RSA")
                                    .generatePublic(
                                        new X509EncodedKeySpec(
                                            Base64.getDecoder()
                                                  .decode(
                                                      Files.readAllBytes(binding == Binding.HTTP_Redirect
                                                          ? Paths.get("src/test/xml/public-key/authn-request-redirect.txt")
                                                          : Paths.get("src/test/xml/public-key/authn-request-post.txt"))

                                                  )));

    try {
      DefaultSAMLv2Service service = new DefaultSAMLv2Service();
      if (binding == Binding.HTTP_Redirect) {
        service.parseRequestRedirectBinding(encodedXML, relayState, request -> new TestRedirectBindingSignatureHelper(Algorithm.RS256, publicKey, signature, true));
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

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationRequest request = binding == Binding.HTTP_Redirect
        ? service.parseRequestRedirectBinding(encodedXML, null, authRequest -> new TestRedirectBindingSignatureHelper())
        : service.parseRequestPostBinding(encodedXML, authRequest -> new TestPostBindingSignatureHelper());

    assertEquals(request.id, "_809707f0030a5d00620c9d9df97f627afe9dcc24");
    assertEquals(request.issuer, "http://sp.example.com/demo1/metadata.php");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress);
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
    assertTrue(response.assertion.conditions.notBefore.isBefore(ZonedDateTime.now()));
    assertTrue(ZonedDateTime.now().isAfter(response.assertion.conditions.notOnOrAfter));
    assertTrue(response.issueInstant.isBefore(ZonedDateTime.now()));
    assertEquals(response.issuer, "https://sts.windows.net/c2150111-3c44-4508-9f08-790cb4032a23/");
    assertEquals(response.status.code, ResponseStatus.Success);
    assertEquals(response.assertion.attributes.get("http://schemas.microsoft.com/identity/claims/displayname").get(0), "Brian Pontarelli");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").get(0), "Brian");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").get(0), "Pontarelli");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").get(0), "brian@inversoft.com");
    assertEquals(response.assertion.subject.nameID.format, NameIDFormat.EmailAddress);
  }

  @Test
  public void parseResponse_handleNilAttribute() throws Exception {
    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/deflated/example-response.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    assertEquals(response.destination, "http://sp.example.com/demo1/index.php?acs");
    assertTrue(response.assertion.conditions.notBefore.isBefore(ZonedDateTime.now()));
    assertEquals(response.issuer, "http://idp.example.com/metadata.php");
    assertEquals(response.status.code, ResponseStatus.Success);
    assertEquals(response.assertion.attributes.get("uid").size(), 1);
    assertEquals(response.assertion.attributes.get("uid").get(0), "test");
    assertEquals(response.assertion.attributes.get("mail").size(), 1);
    assertEquals(response.assertion.attributes.get("mail").get(0), "test@example.com");
    assertEquals(response.assertion.attributes.get("eduPersonAffiliation").size(), 2);
    assertEquals(response.assertion.attributes.get("eduPersonAffiliation").get(0), "users");
    assertEquals(response.assertion.attributes.get("eduPersonAffiliation").get(1), "examplerole1");
    assertEquals(response.assertion.attributes.get("memberOf").size(), 1);
    assertEquals(response.assertion.attributes.get("memberOf").get(0), "");
    // Ensure we can handle
    //  <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true" xsi:type="xs:string"/>
    assertEquals(response.assertion.attributes.get("PersonImmutableID").size(), 1);
    assertNull(response.assertion.attributes.get("PersonImmutableID").get(0));
    assertEquals(response.assertion.subject.nameID.format, NameIDFormat.Transient);
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
    assertTrue(response.assertion.conditions.notBefore.isBefore(ZonedDateTime.now()));
    assertTrue(ZonedDateTime.now().isAfter(response.assertion.conditions.notOnOrAfter));
    assertTrue(response.issueInstant.isBefore(ZonedDateTime.now()));
    assertEquals(response.issuer, "https://sts.windows.net/c2150111-3c44-4508-9f08-790cb4032a23/");
    assertEquals(response.status.code, ResponseStatus.Success);
    assertEquals(response.assertion.attributes.get("http://schemas.microsoft.com/identity/claims/displayname").get(0), "Brian Pontarelli");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").get(0), "Brian");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").get(0), "Pontarelli");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").get(0), "brian@inversoft.com");
    assertEquals(response.assertion.subject.nameID.format, NameIDFormat.EmailAddress);
  }

  @Test
  public void parseResponse_signatureCheck_badSignature() throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    PublicKey key;
    try (InputStream is = Files.newInputStream(Paths.get("src/test/certificates/certificate.cer"))) {
      Certificate cert = cf.generateCertificate(is);
      key = cert.getPublicKey();
    }

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse-badSignature.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    try {
      service.parseResponse(encodedResponse, true, KeySelector.singletonKeySelector(key));
      fail("Should have thrown an exception");
    } catch (SAMLException e) {
      // Should throw
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

  @Test(dataProvider = "bindings")
  public void roundTripAuthnRequest(Binding binding) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String encoded;
    if (binding == Binding.HTTP_Redirect) {
      encoded = service.buildRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.RS256);
    } else {
      X509Certificate cert = generateX509Certificate(kp);
      encoded = service.buildPostAuthnRequest(request, true, kp.getPrivate(), cert, Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    }

    if (binding == Binding.HTTP_Redirect) {
      // Unwind the request
      int start = encoded.indexOf("=");
      int end = encoded.indexOf("&");
      String encodedRequest = URLDecoder.decode(encoded.substring(start + 1, end), "UTF-8");

      // Unwind the RelayState
      start = encoded.indexOf("RelayState=");
      end = encoded.indexOf("&", start);
      String relayState = encoded.substring(start + "RelayState=".length(), end);
      assertEquals(relayState, "Relay-State-String");

      // Unwind the SigAlg
      start = encoded.indexOf("SigAlg=");
      end = encoded.indexOf("&", start);
      String sigAlg = URLDecoder.decode(encoded.substring(start + "SigAlg=".length(), end), "UTF-8");

      // Unwind the Signature
      start = encoded.indexOf("Signature=");
      end = encoded.length();
      String signature = URLDecoder.decode(encoded.substring(start + "Signature=".length(), end), "UTF-8");
      request = service.parseRequestRedirectBinding(encodedRequest, relayState, authRequest -> new TestRedirectBindingSignatureHelper(Algorithm.fromURI(sigAlg), kp.getPublic(), signature, true));
    } else {
      request = service.parseRequestPostBinding(encoded, authRequest -> new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(kp.getPublic()), true));
    }

    // Parse the request
    assertEquals(request.id, "foobarbaz");
    assertEquals(request.issuer, "https://local.fusionauth.io");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress);
    assertEquals(request.version, "2.0");
  }

  @Test(dataProvider = "signatureLocation")
  public void roundTripResponseSignedAssertion(SignatureLocation signatureLocation) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    String encodedXML = service.buildAuthnResponse(response, true, kp.getPrivate(), CertificateTools.fromKeyPair(kp, Algorithm.RS256, "FooBar"), Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, signatureLocation);
    System.out.println(new String(Base64.getMimeDecoder().decode(encodedXML)));
    response = service.parseResponse(encodedXML, true, KeySelector.singletonKeySelector(kp.getPublic()));

    // Assert the signature is in the correct location based upon the signature option provided.
    Document document = parseDocument(encodedXML);
    Node signature = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
    if (signatureLocation == SignatureLocation.Assertion) {
      assertEquals(signature.getParentNode().getLocalName(), "Assertion");
    } else {
      assertEquals(signature.getParentNode().getLocalName(), "Response");
    }

    assertEquals(response.destination, "https://local.fusionauth.io/oauth2/callback");
    assertTrue(response.assertion.conditions.notBefore.isBefore(ZonedDateTime.now()));
    assertTrue(ZonedDateTime.now().isAfter(response.assertion.conditions.notOnOrAfter));
    assertTrue(response.issueInstant.isBefore(ZonedDateTime.now()));
    assertEquals(response.issuer, "https://sts.windows.net/c2150111-3c44-4508-9f08-790cb4032a23/");
    assertEquals(response.status.code, ResponseStatus.Success);
    assertEquals(response.assertion.attributes.get("http://schemas.microsoft.com/identity/claims/displayname").get(0), "Brian Pontarelli");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").get(0), "Brian");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").get(0), "Pontarelli");
    assertEquals(response.assertion.attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").get(0), "brian@inversoft.com");
    assertEquals(response.assertion.subject.nameID.format, NameIDFormat.EmailAddress);
  }

  @DataProvider(name = "signatureLocation")
  public Object[][] signatureLocation() {
    return new Object[][]{
        {SignatureLocation.Assertion},
        {SignatureLocation.Response}
    };
  }

  private X509Certificate generateX509Certificate(KeyPair keyPair) throws IllegalArgumentException {
    try {
      ZonedDateTime now = ZonedDateTime.now();
      X509CertInfo certInfo = new X509CertInfo();
      CertificateX509Key certKey = new CertificateX509Key(keyPair.getPublic());
      certInfo.set(X509CertInfo.KEY, certKey);
      certInfo.set(X509CertInfo.VERSION, new CertificateVersion(1));
      certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid)));
      certInfo.set(X509CertInfo.ISSUER, new X500Name("CN=FusionAuth"));
      certInfo.set(X509CertInfo.SUBJECT, new X500Name("CN=FusionAuth"));
      certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(Date.from(now.toInstant()), Date.from(now.plusYears(10).toInstant())));
      certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16)));

      X509CertImpl impl = new X509CertImpl(certInfo);
      impl.sign(keyPair.getPrivate(), "SHA256withRSA");
      return impl;
    } catch (Exception e) {
      throw new IllegalArgumentException(e);
    }
  }

  private Document parseDocument(String encoded) {
    byte[] bytes = Base64.getMimeDecoder().decode(encoded);
    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
    documentBuilderFactory.setNamespaceAware(true);
    try {
      DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
      return builder.parse(new ByteArrayInputStream(bytes));
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new RuntimeException(e);
    }
  }
}
