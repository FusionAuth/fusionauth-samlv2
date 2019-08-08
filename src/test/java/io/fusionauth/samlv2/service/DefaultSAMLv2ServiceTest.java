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
import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.Inflater;

import io.fusionauth.samlv2.domain.Algorithm;
import io.fusionauth.samlv2.domain.AuthenticationRequest;
import io.fusionauth.samlv2.domain.AuthenticationResponse;
import io.fusionauth.samlv2.domain.MetaData;
import io.fusionauth.samlv2.domain.MetaData.IDPMetaData;
import io.fusionauth.samlv2.domain.MetaData.SPMetaData;
import io.fusionauth.samlv2.domain.NameIDFormat;
import io.fusionauth.samlv2.domain.ResponseStatus;
import io.fusionauth.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Tests the default authentication service.
 *
 * @author Brian Pontarelli
 */
@SuppressWarnings({"unchecked"})
@Test(groups = "unit")
public class DefaultSAMLv2ServiceTest {
  @Test
  public void buildHTTPRedirectAuthnRequest() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String parameters = service.buildHTTPRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.RS256);
    System.out.println(parameters);
//    assertEquals(parameters, "SAMLRequest=eJx9kNtOwzAMhl8lMtdt0rQ7RU2niQlpEiDEBvdZ63WVsmQkKWVvTzZON8Cl7c%2BW%2F6%2Bcvx00eUXnO2skZCkDgqa2TWdaCU%2Bbm2QKxAdlGqWtQQnGwrwqjc%2BF6sPePOJLjz5sTkck8ZLxIo4k9M4Iq3wXS3VAL0It1ou7W8FTJo7OBltbDR8L%2F8PKe3Qh%2Fgbf57mEfQhHQekwDOmQp9a1lDPGKJvRCDW%2Ba69%2B8OIPPKOsOOMxbaRXSwmIBZ%2Fkiifb0bhOijzLk%2BlEYTKabTnjE9bsxuNIet%2FjypydBAlAnr%2FcxXehKi9jV4UoJSokGc9L%2Btm7WLuPEVfLB6u7%2BkQWWtvh2qEK0exOaY9Aq5L%2BZrd6BwQejFI%3D&RelayState=Relay-State-String&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=MCwCFCZDBcWxZD65RY0AR8K4WhNzs0tZAhRQFyc80lMy7yTl9a8UQMSST4wioA%3D%3D");

    // Unwind the request and assert its components
    int start = parameters.indexOf("=");
    int end = parameters.indexOf("&");
    String encodedRequest = URLDecoder.decode(parameters.substring(start + 1, end), "UTF-8");
    byte[] bytes = Base64.getDecoder().decode(encodedRequest);

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
  public void buildIdPMetaData() throws Exception {
    MetaData metaData = new MetaData();
    metaData.id = UUID.randomUUID().toString();
    metaData.entityId = "https://fusionauth.io/samlv2/" + metaData.id;
    metaData.idp = new IDPMetaData();
    metaData.idp.signInEndpoint = "https://fusionauth.io/samlv2/login";
    metaData.idp.logoutEndpoint = "https://fusionauth.io/samlv2/logout";

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
    assertTrue(xml.contains(metaData.idp.signInEndpoint));
    assertTrue(xml.contains(metaData.idp.logoutEndpoint));
    assertTrue(xml.contains("<ns2:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"));

    // Now parse it
    MetaData parsed = service.parseMetaData(xml);
    assertEquals(parsed.id, "_" + metaData.id);
    assertEquals(parsed.entityId, metaData.entityId);
    assertEquals(parsed.idp.signInEndpoint, metaData.idp.signInEndpoint);
    assertEquals(parsed.idp.logoutEndpoint, metaData.idp.logoutEndpoint);
    assertEquals(parsed.idp.certificates.get(0), metaData.idp.certificates.get(0));
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
    AuthenticationResponse response = service.parseResponse(encodedResponse, true, key);

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
  public void roundTripRequest() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    AuthenticationRequest request = new AuthenticationRequest();
    request.id = "foobarbaz";
    request.issuer = "https://local.fusionauth.io";

    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    String parameters = service.buildHTTPRedirectAuthnRequest(request, "Relay-State-String", true, kp.getPrivate(), Algorithm.RS256);
    System.out.println(parameters);

    // Unwind the request
    int start = parameters.indexOf("=");
    int end = parameters.indexOf("&");
    String encodedRequest = URLDecoder.decode(parameters.substring(start + 1, end), "UTF-8");

    // Unwind the RelayState
    start = parameters.indexOf("RelayState=");
    end = parameters.indexOf("&", start);
    String relayState = parameters.substring(start + "RelayState=".length(), end);
    assertEquals(relayState, "Relay-State-String");

    // Unwind the SigAlg
    start = parameters.indexOf("SigAlg=");
    end = parameters.indexOf("&", start);
    String sigAlg = URLDecoder.decode(parameters.substring(start + "SigAlg=".length(), end), "UTF-8");

    // Unwind the Signature
    start = parameters.indexOf("Signature=");
    end = parameters.length();
    String signature = URLDecoder.decode(parameters.substring(start + "Signature=".length(), end), "UTF-8");

    // Parse the request
    request = service.parseRequest(encodedRequest, relayState, signature, true, kp.getPublic(), Algorithm.fromURI(sigAlg));
    assertEquals(request.id, "foobarbaz");
    assertEquals(request.issuer, "https://local.fusionauth.io");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress);
    assertEquals(request.version, "2.0");
  }

  @Test
  public void roundTripResponse() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    byte[] ba = Files.readAllBytes(Paths.get("src/test/xml/encodedResponse.txt"));
    String encodedResponse = new String(ba);
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    AuthenticationResponse response = service.parseResponse(encodedResponse, false, null);

    String encodedXML = service.buildAuthnResponse(response, true, kp.getPrivate(), CertificateTools.fromKeyPair(kp, Algorithm.RS256, "FooBar"), Algorithm.RS256, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
    System.out.println(new String(Base64.getDecoder().decode(encodedXML)));
    response = service.parseResponse(encodedXML, true, kp.getPublic());

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
}
