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
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
import io.fusionauth.samlv2.util.SAMLTools;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import sun.security.rsa.RSAPublicKeyImpl;
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

  @Test(enabled = false)
  public void parseRequest_compassSecurity() throws Exception {
    String encodedXML = "PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIg0KICAgICAgICAgICAgICAgICAgICB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzdmZTUxMGNjOGU1MWFhNDE1NThhIg0KICAgICAgICAgICAgICAgICAgICBJc3N1ZUluc3RhbnQ9IjIwMjEtMDEtMjFUMTY6NDY6MDVaIiBQcm92aWRlck5hbWU9IlNpbXBsZSBTQU1MIFNlcnZpY2UgUHJvdmlkZXIiDQogICAgICAgICAgICAgICAgICAgIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cDovL2xvY2FsaG9zdDo3MDcwL3NhbWwvc3NvIg0KICAgICAgICAgICAgICAgICAgICBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo5MDExL3NhbWx2Mi9sb2dpbi81YjJlNDgzZi03NTcyLTQ4NzktODE3ZS0xYTkwYWM0NGU3NTciDQogICAgICAgICAgICAgICAgICAgIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCIgVmVyc2lvbj0iMi4wIj4NCiAgPHNhbWw6SXNzdWVyPnVybjpleGFtcGxlOnNwPC9zYW1sOklzc3Vlcj4NCiAgPFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQogICAgPFNpZ25lZEluZm8+DQogICAgICA8Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPg0KICAgICAgPFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz4NCiAgICAgIDxSZWZlcmVuY2UgVVJJPSIjXzdmZTUxMGNjOGU1MWFhNDE1NThhIj4NCiAgICAgICAgPFRyYW5zZm9ybXM+DQogICAgICAgICAgPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+DQogICAgICAgICAgPFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPg0KICAgICAgICA8L1RyYW5zZm9ybXM+DQogICAgICAgIDxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz4NCiAgICAgICAgPERpZ2VzdFZhbHVlPjV4V2cvaWRqOGpNV2Z3ZWRmaksyQkVZa2QveUxXY2pNa2ZKK1ZmOHQrRkE9PC9EaWdlc3RWYWx1ZT4NCiAgICAgIDwvUmVmZXJlbmNlPg0KICAgIDwvU2lnbmVkSW5mbz4NCiAgICA8U2lnbmF0dXJlVmFsdWU+DQogICAgICBsZ05CSEZ4UHFueHVKRmVRa0cwN3dNY0JwZll3TkVBc2pMeWpQTTBsQit5Nm8rNEtDSzN0U2padXVSUVlNWTRJb3J6Uk95b3piZGtsRitCT2UxL0tKNFhxRGhFaXFlbUEyTGszcEliakJQbit6NDdGcER0NWdsQUVxY3NmMlI2RDhKTndkNWJxSmgxYnVITXNUQ3dIOFhPVHZpdHlxQXZrZmp4WVhNU290SDFWSWxrRWxjZFF6aXA5ZlhsZW1ZdExCdXoybG5sTHYyS01DSkRpYTlQTzZrSHQySTRBL2s0WXBNRmx2NlF0aGlPcjdlVjROOWIxVk43VUxYRHJlUS9OUDhtZWdtWGVBcWxaMC81VnlXdGRYQ1E0QUlSUVlUeW5mTlZ3TDA1VG5JOXNYZDl5WTdPbXk5WVJwdEYzaHZBWVFqd0t1ak90bjNGUnJNSldKMzRha3c9PQ0KICAgIDwvU2lnbmF0dXJlVmFsdWU+DQogICAgPEtleUluZm8+DQogICAgICA8WDUwOURhdGE+DQogICAgICAgIDxYNTA5Q2VydGlmaWNhdGU+DQogICAgICAgICAgTUlJRFV6Q0NBanVnQXdJQkFnSUpBUEowbUE2V3pPcHZNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HQXhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJRXdwRFlXeHBabTl5Ym1saE1SWXdGQVlEVlFRSEV3MVRZVzRnUm5KaGJtTnBjMk52TVJBd0RnWURWUVFLRXdkS1lXNXJlVU52TVJJd0VBWURWUVFERXdsc2IyTmhiR2h2YzNRd0hoY05NVFF3TXpFeU1UazBOak16V2hjTk1qY3hNVEU1TVRrME5qTXpXakJnTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCeE1OVTJGdUlFWnlZVzVqYVhOamJ6RVFNQTRHQTFVRUNoTUhTbUZ1YTNsRGJ6RVNNQkFHQTFVRUF4TUpiRzlqWVd4b2IzTjBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRsTkR5NERSMnRoWjJERGNpSVRvZlVwd1laY25Yay85cHFEdDhWMTZqQkQwMnVPZC9UZHlzZ2lLTGpyWlpiQy9YME9YMUVGZTVkTjY1VXJMT0RRQkJ6WjMvOFBZejY4MTlNS2M5aXJWOCs3MzJINWRHd3pnbVlCWUQrcXFmNEJjUjM2TDdUam1Pd2prZSsxY01jR2crV1hWU1hRTS9kalN4aFFIaldOamtSdDFUL21MZmxxTXFwb3B6Y21BUFFETEVIRXJ0dWFtOVh0dWRqaUZNOHI1anp2bXUvVXBJUGliYndBWThxM3NUUHBFN0pCTHI2SXk0cEJBY2lMbFhhNE5yRFE4YUw4akZwaWhqdm0rdUhWTUhNR215bkdpY0dRTGdyRktPV3M2NTVtVlZXWGZET2U2SjVwaUJYcjFteW5uQnN0ZGRTYWxaNWFMQVdGOGc2c3pmUUlEQVFBQm94QXdEakFNQmdOVkhSTUJBZjhFQWpBQU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ2xaeStnTVlrTmZvK2RRakV1dmJ2eDYyTU1SM1dka3BmZXk0M1pnUHF4MTh2cEcwUDdhSXFUeWJreFRraGkvQXc4cExEY0l2QVBaSHFsTWZMQ05Cci80K3NucXJMbzNPaUdaSTFobDlRT0czaFFta3JqVDEwaGx5WFJTM29UbmpENWJoRGoraW5iRzFpOVFSSzdQTzBQUXFXaElLZ3J0THlZcDNXdlM2WjljWVh3UXQ1RmNZYmhLcCtDK2t2Q3pxK1RmYlFhbWx2ZWhXakJVTlIyN0NFMTFNLy9XVEYwbmZiT0Z1MzJFQzZrQjBFR2Q2UFRJd2h0eTJ6SHhnKyt1WU1qQVVMK1pOdU5pYU1jMzU1b1h2THRoMXE1cmszR2EzdW5wQmptUTdvYlUyLzQvV2RKblBmdmxEMmt0QVYvUzVkVlNLU0RObWthZzhJWDBuSGIvMUZODQogICAgICAgIDwvWDUwOUNlcnRpZmljYXRlPg0KICAgICAgPC9YNTA5RGF0YT4NCiAgICA8L0tleUluZm8+DQogIDwvU2lnbmF0dXJlPg0KICA8c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPg0KICA8c2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0IENvbXBhcmlzb249ImV4YWN0Ij4NCiAgICA8c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydA0KICAgIDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj4NCiAgPC9zYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQ+DQo8L3NhbWxwOkF1dGhuUmVxdWVzdD4=";
    DefaultSAMLv2Service service = new DefaultSAMLv2Service();
    PublicKey publicKey = new RSAPublicKeyImpl
        (new BigInteger("23016430918823899869174537266594866915196701755262955756947374683306171050449785978041642070945082562110926617344211216571596575890159654912559343561454566120924390651417182396241104494630512996615232908509829811443784313485862019497373006302688901954848508137355590138442254765794572625586049567608157223736747587462558785268970406066201827350377828581492579969240135441642716939367190425379788145244337250560138881783025442595121210838086638484878363941229167629103738547784336822433469701246494321129732432091196962736034404069520496182669787723781485938596516343326251546340541402004104537790138422441873446220669"),
            new BigInteger("65537"));
    TestPostBindingSignatureHelper signatureHelper = new TestPostBindingSignatureHelper(KeySelector.singletonKeySelector(publicKey), true);
    AuthenticationRequest request = service.parseRequestPostBinding(encodedXML, authRequest -> signatureHelper);

    assertEquals(request.id, "_7fe510cc8e51aa41558a");
    assertEquals(request.issuer, "urn:example:sp");
    assertEquals(request.nameIdFormat, NameIDFormat.EmailAddress);
    assertEquals(request.version, "2.0");
  }

  @Test
  public void parseRequest_expandedEntity() throws Exception {
    // Expanded entity, fail. The entity definition is within the DOCTYPE, which is not allowed, the error will be with regards to the DOCTYPE.
    try {
      DefaultSAMLv2Service service = new DefaultSAMLv2Service();
      byte[] xml = Files.readAllBytes(Paths.get("src/test/xml/authn-request-expanded-entity.xml"));
      String deflated = SAMLTools.deflateAndEncode(xml);
      AuthenticationRequest request = service.parseRequestRedirectBinding(deflated, null, authRequest -> new TestRedirectBindingSignatureHelper());
      fail("Expected an exception because we are declaring a DOCTYPE and expanding an entity. The issuer is now set to [" + request.issuer + "] which is not good.");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Unable to parse SAML v2.0 authentication response");
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
      AuthenticationRequest request = service.parseRequestRedirectBinding(deflated, null, authRequest -> new TestRedirectBindingSignatureHelper());
      fail("Expected an exception because we are declaring a DOCTYPE. The issuer is now set to [" + request.issuer + "] which is not good.");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Unable to parse SAML v2.0 authentication response");
      assertEquals(e.getCause().getClass().getCanonicalName(), "org.xml.sax.SAXParseException");
      assertEquals(e.getCause().getMessage(), "DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.");
    } finally {
      if (tempFile != null) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  @Test
  public void parseRequest_hasDocType() throws Exception {
    // Has DOCTYPE, fail. No DOCTYPE for you!
    try {
      DefaultSAMLv2Service service = new DefaultSAMLv2Service();
      byte[] xml = Files.readAllBytes(Paths.get("src/test/xml/authn-request-has-doctype.xml"));
      String deflated = SAMLTools.deflateAndEncode(xml);
      service.parseRequestRedirectBinding(deflated, null, authRequest -> new TestRedirectBindingSignatureHelper());
      fail("expected an exception because we are declaring a DOCTYPE");
    } catch (SAMLException e) {
      assertEquals(e.getMessage(), "Unable to parse SAML v2.0 authentication response");
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
