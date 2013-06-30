package org.inversoft.samlv2.service;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import java.io.ByteArrayInputStream;
import java.util.zip.Inflater;

import org.inversoft.samlv2.domain.AuthenticationRequest;
import org.inversoft.samlv2.domain.NameIDFormat;
import org.inversoft.samlv2.domain.jaxb.oasis.protocol.AuthnRequestType;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import sun.misc.BASE64Decoder;

/**
 * Tests the default authentication service.
 *
 * @author Brian Pontarelli
 */
public class DefaultAuthenticationRequestServiceTest {
  @Test
  public void build() throws Exception {
    DefaultAuthenticationRequestService service = new DefaultAuthenticationRequestService();
    AuthenticationRequest request = service.buildRequest("testing 123", NameIDFormat.EmailAddress);

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
