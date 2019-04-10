/*
 * Copyright (c) 2019, Inversoft Inc., All Rights Reserved
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

package io.fusionauth.samlv2.domain;

/**
 * Available algorithms to sign the SAML XML documents.
 *
 * @author Brian Pontarelli
 */
public enum Algorithm {
  /**
   * ECDSA using P-256 and SHA-256
   * <p>
   * OID: 1.2.840.10045.3.1.7
   * <p>
   * - prime256v1 / secp256r1
   */
  ES1("SHA1withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"),

  /**
   * ECDSA using P-256 and SHA-256
   * <p>
   * OID: 1.2.840.10045.3.1.7
   * <p>
   * - prime256v1 / secp256r1
   */
  ES256("SHA256withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),

  /**
   * ECDSA using P-384 and SHA-384
   * <p>
   * OID: 1.3.132.0.34
   * <p>
   * - secp384r1 / secp384r1
   */
  ES384("SHA384withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"),

  /**
   * ECDSA using P-521 and SHA-512
   * <p>
   * OID: 1.3.132.0.35
   * <p>
   * - prime521v1 / secp521r1
   */
  ES512("SHA512withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-1
   */
  RS1("SHA1withRSA", "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-256
   */
  RS256("SHA256withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-384
   */
  RS384("SHA384withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-512
   */
  RS512("SHA512withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");

  public final String name;

  public final String uri;

  Algorithm(String name, String uri) {
    this.name = name;
    this.uri = uri;
  }

  public static Algorithm fromURI(String uri) {
    for (Algorithm alg : values()) {
      if (alg.uri.equals(uri)) {
        return alg;
      }
    }

    return null;
  }
}
