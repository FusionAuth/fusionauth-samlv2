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

import org.inversoft.samlv2.domain.AuthenticationRequest;
import org.inversoft.samlv2.domain.NameIDFormat;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import org.testng.annotations.Test;
import sun.misc.BASE64Decoder;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import java.io.ByteArrayInputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.zip.Inflater;

import static org.testng.Assert.assertEquals;

/**
 * Tests the default authentication service.
 *
 * @author Brian Pontarelli
 */
@Test(groups = "unit")
public class DefaultAuthenticationServiceTest {
  @Test
  public void buildRequest() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
    kpg.initialize(512);
    KeyPair kp = kpg.generateKeyPair();

    DefaultAuthenticationService service = new DefaultAuthenticationService();
    AuthenticationRequest request = service.buildRequest("testing 123", NameIDFormat.EmailAddress, true, kp);
    assertEquals(request.toRedirectURL(new URL("http://www.example.com/samlv2/idp"))
                        .toString(), "http://www.example.com/samlv2/idp?SAMLRequest=" + URLEncoder.encode(request.encodedRequest, "UTF-8"));

    JAXBContext context = JAXBContext.newInstance(AuthnRequestType.class);
    Unmarshaller unmarshaller = context.createUnmarshaller();

    // Decode and inflate the result and ensure it is equal to the raw and can be unmarshalled
    byte[] bytes = new BASE64Decoder().decodeBuffer(request.encodedRequest);
    byte[] inflatedBytes = new byte[request.rawResult.length];
    Inflater inflater = new Inflater();
    inflater.setInput(bytes);
    int length = inflater.inflate(inflatedBytes);

    AuthnRequestType fromEncoded = (AuthnRequestType) unmarshaller.unmarshal(new ByteArrayInputStream(inflatedBytes, 0, length));
    AuthnRequestType fromRaw = (AuthnRequestType) unmarshaller.unmarshal(new ByteArrayInputStream(request.rawResult));

    assertEquals(fromEncoded.getIssuer().getValue(), "testing 123");
    assertEquals(fromEncoded.getID(), request.id);
    assertEquals(fromRaw.getIssuer().getValue(), "testing 123");
    assertEquals(fromRaw.getID(), request.id);
  }
}
