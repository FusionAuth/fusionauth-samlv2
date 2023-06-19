/*
 * Copyright (c) 2021-2022, Inversoft Inc., All Rights Reserved
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
import javax.crypto.spec.PSource;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import static org.testng.Assert.assertTrue;

/**
 * @author Daniel DeGroff
 */
public class SAMLToolsTest {
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

  @Test
  public void decrypt() throws Exception {
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT);
    RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC00IIWIKOujKRbfZCedB1NTdFjxJ6ez1FXAJYX6KJU0/JWAnbDWqhonK6193kjNw80zjLrH/DqMlb0/1wzcE5iAmm7wKfHQXsYhhMgH1TBHgytFS/1dv1PwnNH/oMhYQqkTpN08uPxvOI7xvVul3davoS2LZVKJsZ6ZP0EGo0TRMMfi0KG+FXY1+WbldGowCLanQVkNub4i02V/aSLQwh2IgsLP2rIzEeGUbiRzxhVWCqPOSK1I4TygayW71knSF4Retr92psqzv5igmnUJ5NwAyo3piEQHtgQSyK09TE8wMaSUG1FKw0qxfaTpv/dVLGQhcEagIVZ7s2gciA4vy87AgMBAAECggEAIuPRFj/6FaZh2J2kGE9DkDUh4GSCTxamFWmxjK+BE2lKa7pR/GQz9uu08rvsDhWDw6a+QIyLSkWobeIQgoR7O4JHsMj+Fv7Vp+fHLP2etxz7STK7bFwniQp2gD/mQbyd9xKKdZigz3apGOvNVCe6CjKVHSoyknpk9h0ijXYqHrtkmRtrxR5asaUur5TYEY+wy5jaZLRLYP/XY2F6s6OtWPs4CNF0EN4KRHUxXYuLcN1ujwnuZUcB6OXCiAo0Y7JFi+Jj21uN73Ptt7ffBAYKF78Yss7OAPIj9vSUQdoCKpyM4H9TzXsmTQ9EmyTHAlw34ed6P1U7jIQ9oiBdNM6nsQKBgQDs3ZqWt8KK+PeTnTh3abCq4vldLEdq35fyU7U3AuzH/cSTbu/wJZxMT4KSQVXTkVXjpo63AdzL6hv657a1ftVQy+AdQXgk3/pdS4+WBSIvaarVTJBX8M7JfHI5/VEUKUmjrK/NLz+3XGzR1Uz5yhvfJnz+sQ98jVHe+iWnoqHYZwKBgQDDa8NOzLKJfONE5pu1stFlCKanQXn9Tl5v4fJPYzPbuZQQU8SXIkY56yZSbiw9/vsfV+oT8LURDb+L6f5eoSX6zn4fO+P0RI7OR8jJcjQHjnqn4NoXWTTUx72i/WUdgkObSNEVE7a00zckIL9w22fnTZWxJeELWuOURmKCcQf+DQKBgCvUacmf4UjT/wP6oLs//Gfyrg/2pJR7IWO+55ZxXR04sQpTCeUXII/iWpfzrQ0EJK+GX3wvxQqanGjWPbHh8VkNEMB5H+E67NocpEovUv8Q/4KOs1sCfVE9TOm8HSes6Cp4RuOh7ZlhaeV+IctLAdNODO0YGHSEtfSbtyII7wfbAoGAM045ipinTv1g1ZgNzVhTLUlmJ4dDNcO7e3hAm6MZ3FgOjXLQrDUtZstb1kxihSxKVeJI7E9H2mBXp64ZQFLim8RWzHB22oydSX8DMhAvpMQ9Y5He8D5VZn/CQ+ZvA55NjZlCe1wfnb3OPkfyuvh/gPSXllixir+j/Cu2dTSjuokCgYAFxTKPFYDv2niUBm1kyY/ZoM7FeCskizR6SdwvQZeMPS4NsbjEpDawH56czWg+WS9Lhlohcp/SHBiTtcAayXcQbwNRbJVNvOXCbru4WGQuIfDKZkzJyS5XLkbBfz6cHwkSit3gJLpHTeb2J8y+AbJ6lcmYnJTpo/0P/yQWH+qHhQ==")));
    rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
    byte[] encryptedKey = Base64.getDecoder().decode("n6iYhqSjEhwCUqC0IL0PTe4Ds2G1CDewv4fPjj0FNLIOZSb1hYVvObv9vprvBym20F4NefyUASus9msoorbIQVkMyGuGCNABV3jvm7DzSz2PU6YwwF/vjT7Z+cVtdfgCkOahBaiTTRqHuvsAF7BHrNFUIkqOMsoF9V6ZJSv9fWTuZjyqxVXp+9pKk0sTFRjS+zckahWaaIkm4MFQGV/u2NLA5cde6vyw4Xb34WIrgFT5cLrXf1yyONFJwi5cGi4b0Oo/i4xO7zbZQJ7CpBzk6i7NOdZtRtRRRvfWpgLZvIni4RbUTJPleoLVX4Xogf42yvXBahn6wuXOJCOejI0OOg==");
    byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);

    Cipher aesCipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
    SecretKey aesKey = new SecretKeySpec(decryptedKey, "AES");
    byte[] encryptedMessage = Base64.getDecoder().decode("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");
    byte[] iv = new byte[16];
    System.arraycopy(encryptedMessage, 0, iv, 0, 16);
    byte[] encryptedAssertion = new byte[encryptedMessage.length - 16];
    System.arraycopy(encryptedMessage, 16, encryptedAssertion, 0, encryptedAssertion.length);
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
    byte[] decryptedAssertion = aesCipher.doFinal(encryptedAssertion);
    String str = new String(decryptedAssertion, StandardCharsets.UTF_8);
    System.out.println(str);
  }
}
