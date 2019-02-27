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
import javax.xml.bind.Unmarshaller;
import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.Inflater;

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
@SuppressWarnings({"unchecked", "ResultOfMethodCallIgnored"})
@Test(groups = "unit")
public class DefaultSAMLServiceTest {
  @Test
  public void buildHTTPRedirectAuthnRequest() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
    kpg.initialize(512);
    KeyPair kp = kpg.generateKeyPair();

    DefaultSAMLService service = new DefaultSAMLService();
    String parameters = service.buildHTTPRedirectAuthnRequest("https://local.fusionauth.io", "Relay-State-String", true, kp.getPrivate());
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
    assertTrue(fromEncoded.getValue().getID().startsWith("id"));
    UUID.fromString(fromEncoded.getValue().getID().substring(2)); // This will ensure it is a UUID after the "id" prefix
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
    assertEquals(sigAlg, "http://www.w3.org/2000/09/xmldsig#dsa-sha1");
  }
}
