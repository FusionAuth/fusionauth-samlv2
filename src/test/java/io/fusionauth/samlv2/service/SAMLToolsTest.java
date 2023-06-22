/*
 * Copyright (c) 2021-2023, Inversoft Inc., All Rights Reserved
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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import io.fusionauth.samlv2.domain.SAMLException;
import io.fusionauth.samlv2.util.SAMLRequestParameters;
import io.fusionauth.samlv2.util.SAMLTools;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * @author Daniel DeGroff
 */
public class SAMLToolsTest {
  private final String aesKeyBase64 = "F2FnwVEH31NF+mtpLuDAPsZnTtV36nvb8JUCyVk5rnA=";

  private final String aesKeyCipherTextBase64 = "n6iYhqSjEhwCUqC0IL0PTe4Ds2G1CDewv4fPjj0FNLIOZSb1hYVvObv9vprvBym20F4NefyUASus9msoorbIQVkMyGuGCNABV3jvm7DzSz2PU6YwwF/vjT7Z+cVtdfgCkOahBaiTTRqHuvsAF7BHrNFUIkqOMsoF9V6ZJSv9fWTuZjyqxVXp+9pKk0sTFRjS+zckahWaaIkm4MFQGV/u2NLA5cde6vyw4Xb34WIrgFT5cLrXf1yyONFJwi5cGi4b0Oo/i4xO7zbZQJ7CpBzk6i7NOdZtRtRRRvfWpgLZvIni4RbUTJPleoLVX4Xogf42yvXBahn6wuXOJCOejI0OOg==";

  private final String assertionCipherTextBase64 = "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";

  private final byte[] iv = new byte[]{69, 26, 3, 44, -5, 4, 47, -84, 42, -59, 33, 106, -85, -61, 34, 64};

  private final String rsaCertBase64 = "MIIDgDCCAmgCCQDRiZeggGkhDzANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCWFgxCzAJBgNVBAgMAkNPMQ8wDQYDVQQHDAZEZW52ZXIxGDAWBgNVBAoMD0Z1c2lvbkF1dGgtVGVzdDEUMBIGA1UECwwLRW5naW5lZXJpbmcxJDAiBgNVBAMMG2FjY291bnQtbG9jYWwuZnVzaW9uYXV0aC5pbzAeFw0yMzA2MTkxNDQ0NTRaFw0zMzA2MTYxNDQ0NTRaMIGBMQswCQYDVQQGEwJYWDELMAkGA1UECAwCQ08xDzANBgNVBAcMBkRlbnZlcjEYMBYGA1UECgwPRnVzaW9uQXV0aC1UZXN0MRQwEgYDVQQLDAtFbmdpbmVlcmluZzEkMCIGA1UEAwwbYWNjb3VudC1sb2NhbC5mdXNpb25hdXRoLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtNCCFiCjroykW32QnnQdTU3RY8Sens9RVwCWF+iiVNPyVgJ2w1qoaJyutfd5IzcPNM4y6x/w6jJW9P9cM3BOYgJpu8Cnx0F7GIYTIB9UwR4MrRUv9Xb9T8JzR/6DIWEKpE6TdPLj8bziO8b1bpd3Wr6Eti2VSibGemT9BBqNE0TDH4tChvhV2Nflm5XRqMAi2p0FZDbm+ItNlf2ki0MIdiILCz9qyMxHhlG4kc8YVVgqjzkitSOE8oGslu9ZJ0heEXra/dqbKs7+YoJp1CeTcAMqN6YhEB7YEEsitPUxPMDGklBtRSsNKsX2k6b/3VSxkIXBGoCFWe7NoHIgOL8vOwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB7rEqp6BMabPx4Ese8ubk5fKgL5hJvwIljO60LgCQNA6k/HOJUobV5r803SK+3z0nQ4qLuZLGklATcGump08Sym896U5j/ojx6S7xWn391Nl2E5OVB/U6fh3XKjLWnSQLFWTbuePGc37VbPWpilS9D672eG+zxqdWHC7PZxgWpCfyjINUX9jcLZFQeWbG2HQbhY9kucSTN2WBnPqFEWhDJ7q3JrDluJEboBMpYmaJ/fmM4KxSV8uYXvRs2p4QJYTx05mDl0A3hiep22vyyo65z1FSD/fNVPgWphSjqhzVogVgoaLyt3vLGYqYlV9URK7/1h44RCBA557z5OlDOW+tM";

  private final String rsaPrivateKeyBase64 = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC00IIWIKOujKRbfZCedB1NTdFjxJ6ez1FXAJYX6KJU0/JWAnbDWqhonK6193kjNw80zjLrH/DqMlb0/1wzcE5iAmm7wKfHQXsYhhMgH1TBHgytFS/1dv1PwnNH/oMhYQqkTpN08uPxvOI7xvVul3davoS2LZVKJsZ6ZP0EGo0TRMMfi0KG+FXY1+WbldGowCLanQVkNub4i02V/aSLQwh2IgsLP2rIzEeGUbiRzxhVWCqPOSK1I4TygayW71knSF4Retr92psqzv5igmnUJ5NwAyo3piEQHtgQSyK09TE8wMaSUG1FKw0qxfaTpv/dVLGQhcEagIVZ7s2gciA4vy87AgMBAAECggEAIuPRFj/6FaZh2J2kGE9DkDUh4GSCTxamFWmxjK+BE2lKa7pR/GQz9uu08rvsDhWDw6a+QIyLSkWobeIQgoR7O4JHsMj+Fv7Vp+fHLP2etxz7STK7bFwniQp2gD/mQbyd9xKKdZigz3apGOvNVCe6CjKVHSoyknpk9h0ijXYqHrtkmRtrxR5asaUur5TYEY+wy5jaZLRLYP/XY2F6s6OtWPs4CNF0EN4KRHUxXYuLcN1ujwnuZUcB6OXCiAo0Y7JFi+Jj21uN73Ptt7ffBAYKF78Yss7OAPIj9vSUQdoCKpyM4H9TzXsmTQ9EmyTHAlw34ed6P1U7jIQ9oiBdNM6nsQKBgQDs3ZqWt8KK+PeTnTh3abCq4vldLEdq35fyU7U3AuzH/cSTbu/wJZxMT4KSQVXTkVXjpo63AdzL6hv657a1ftVQy+AdQXgk3/pdS4+WBSIvaarVTJBX8M7JfHI5/VEUKUmjrK/NLz+3XGzR1Uz5yhvfJnz+sQ98jVHe+iWnoqHYZwKBgQDDa8NOzLKJfONE5pu1stFlCKanQXn9Tl5v4fJPYzPbuZQQU8SXIkY56yZSbiw9/vsfV+oT8LURDb+L6f5eoSX6zn4fO+P0RI7OR8jJcjQHjnqn4NoXWTTUx72i/WUdgkObSNEVE7a00zckIL9w22fnTZWxJeELWuOURmKCcQf+DQKBgCvUacmf4UjT/wP6oLs//Gfyrg/2pJR7IWO+55ZxXR04sQpTCeUXII/iWpfzrQ0EJK+GX3wvxQqanGjWPbHh8VkNEMB5H+E67NocpEovUv8Q/4KOs1sCfVE9TOm8HSes6Cp4RuOh7ZlhaeV+IctLAdNODO0YGHSEtfSbtyII7wfbAoGAM045ipinTv1g1ZgNzVhTLUlmJ4dDNcO7e3hAm6MZ3FgOjXLQrDUtZstb1kxihSxKVeJI7E9H2mBXp64ZQFLim8RWzHB22oydSX8DMhAvpMQ9Y5He8D5VZn/CQ+ZvA55NjZlCe1wfnb3OPkfyuvh/gPSXllixir+j/Cu2dTSjuokCgYAFxTKPFYDv2niUBm1kyY/ZoM7FeCskizR6SdwvQZeMPS4NsbjEpDawH56czWg+WS9Lhlohcp/SHBiTtcAayXcQbwNRbJVNvOXCbru4WGQuIfDKZkzJyS5XLkbBfz6cHwkSit3gJLpHTeb2J8y+AbJ6lcmYnJTpo/0P/yQWH+qHhQ==";

  private final String samlAssertion = """
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
        <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
          <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
          <saml:Subject>
            <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
            <saml:AudienceRestriction>
              <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>
            <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
              <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>""";

  @Test
  public void decrypt() throws Exception {
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT);
    RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKeyBase64)));
    rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
    byte[] encryptedKey = Base64.getDecoder().decode(aesKeyCipherTextBase64);
    byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);

    Cipher aesCipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
    SecretKey aesKey = new SecretKeySpec(decryptedKey, "AES");
    byte[] encryptedMessage = Base64.getDecoder().decode(assertionCipherTextBase64);
    byte[] iv = new byte[16];
    System.arraycopy(encryptedMessage, 0, iv, 0, 16);
    byte[] encryptedAssertion = new byte[encryptedMessage.length - 16];
    System.arraycopy(encryptedMessage, 16, encryptedAssertion, 0, encryptedAssertion.length);
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
    byte[] decryptedAssertion = aesCipher.doFinal(encryptedAssertion);
    String str = new String(decryptedAssertion, StandardCharsets.UTF_8);
    assertEquals(str, samlAssertion);
  }

  @Test
  public void encrypt_decrypt() throws Exception {
    // Encrypt the assertion with AES key
    Cipher aesCipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
    SecretKey aesKey = new SecretKeySpec(Base64.getDecoder().decode(aesKeyBase64), "AES");
    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
    // ISO10126Padding pads with random values at the end of the plaintext
    byte[] encryptedAssertion = aesCipher.doFinal(samlAssertion.getBytes(StandardCharsets.UTF_8));
    // The XML CipherValue contains the IV followed by ciphertext, then base64-encoded
    byte[] ivPlusAssertion = new byte[encryptedAssertion.length + iv.length];
    System.arraycopy(iv, 0, ivPlusAssertion, 0, iv.length);
    System.arraycopy(encryptedAssertion, 0, ivPlusAssertion, iv.length, encryptedAssertion.length);
    // Up to 16 bytes (128 bits) of padding may be added by ISO10126Padding. Remove the last 24 characters from base64 encoded value
    // The assertions for decrypted data will ensure the result is correct
    String base64 = Base64.getEncoder().encodeToString(ivPlusAssertion);
    assertEquals(base64.substring(0, base64.length() - 24), assertionCipherTextBase64.substring(0, assertionCipherTextBase64.length() - 24));

    // Load the RSA cert from encoded PEM string
    Certificate rsaCert = CertificateFactory.getInstance("X.509")
                                            .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(rsaCertBase64)));
    // Encrypt the AES key with RSA cert
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
    rsaCipher.init(Cipher.ENCRYPT_MODE, rsaCert);
    byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
    // Cannot assert on the encrypted key values because of randomness in the padding algorithm

    // Decrypt the AES key with RSA private key
    RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKeyBase64)));
    rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);
    assertEquals(Base64.getEncoder().encodeToString(decryptedAesKey), aesKeyBase64);

    // Decrypt the assertion using the decrypted key
    aesKey = new SecretKeySpec(decryptedAesKey, "AES");
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
    byte[] decryptedAssertion = aesCipher.doFinal(encryptedAssertion);
    assertEquals(new String(decryptedAssertion, StandardCharsets.UTF_8), samlAssertion);
  }

  @Test
  public void parseQueryString() {
    // Account for null
    SAMLRequestParameters actual = SAMLTools.parseQueryString(null);

    assertNull(actual.RelayState);
    assertNull(actual.SAMLRequest);
    assertNull(actual.SigAlg);
    assertNull(actual.Signature);

    assertNull(actual.urlDecodedRelayState());
    assertNull(actual.urlDecodedSAMLRequest());
    assertNull(actual.urlDecodedSigAlg());
    assertNull(actual.urlDecodedSignature());
  }

  @Test
  public void truncatedRequest() throws SAMLException {
    // Ensure we can handle a truncated deflated AuthN request.
    // - As long as this test doesn't hang we are good.
    String truncated = "fVPBjpswEL1X6j8g7gHDJqFYSSqaqGqkbRcF2kMvlWsPjSVsU3vYTf++hk22qbSEC5L95s2b9zwrx1Tb0aLHoz7A7x4cBifVakfHi3XYW00Nc9JRzRQ4ipxWxed7mkaEdtag4aYN374JXvn+8dymYc6BRWn0BM9+tw5/vCN5RrKGkDvCFoKQZUp4LnLR5FmzTDPWQC44T+cTHN/AOt9hHfqGE5DSmkcpwH7xAtdhVQbozZiS5FwPe+2QafScJJnPSDZLlnV6RxcpnS++TxTuPKfUDEctR8SOxrEUXQQnproWIm5UXFUPFdhHySHqjt202tH7D1ILqX/ddvjnM8jRT3VdzsqHqp5gLS5RbI12vQJ7FvL1cP8i1/2vVoAySewbwGmQ+55xF24G9tWQPB2dsptbtQqQCYZsKF/F11UvNB0dUtnvStNK/if4aKxiOD1zEiXjiRSzZoRSUEy2hRAWnAuDom3N09YCQ5802h7C+LrXeRFAjGvhrUA4YbA1qmNWuiE5PwTH5zEvg15jt61/";
    SAMLTools.decodeAndInflate(truncated);
  }
}
