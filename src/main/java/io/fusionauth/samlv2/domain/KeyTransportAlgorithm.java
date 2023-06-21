/*
 * Copyright (c) 2023, Inversoft Inc., All Rights Reserved
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
 * Available algorithms to encrypt symmetric keys for transport.
 *
 * @author Spencer Witt
 */
public enum KeyTransportAlgorithm {
  /**
   * RSA Version 1.5
   */
  RSAv15("RSA-v1.5", "http://www.w3.org/2001/04/xmlenc#rsa-1_5", "RSA"),

  /**
   * RSA with OAEP using MGF1 with SHA1
   */
  RSA_OAEP_MGF1P("RSA OAEP with MGF1 with SHA1 ", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "RSA/ECB/OAEPPadding"),

  /**
   * RSA with OAEP using MGF1
   */
  RSA_OAEP("RSA OAEP with MGF1", "http://www.w3.org/2009/xmlenc11#rsa-oaep", "RSA/ECB/OAEPPadding");

  public final String name;

  public final String transformation;

  public final String uri;

  KeyTransportAlgorithm(String name, String uri, String transformation) {
    this.name = name;
    this.uri = uri;
    this.transformation = transformation;
  }

  public static KeyTransportAlgorithm fromURI(String uri) {
    for (KeyTransportAlgorithm alg : values()) {
      if (alg.uri.equals(uri)) {
        return alg;
      }
    }

    return null;
  }
}
