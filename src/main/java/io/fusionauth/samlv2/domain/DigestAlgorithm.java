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
 * Available message digest algorithms.
 *
 * @author Spencer Witt
 */
public enum DigestAlgorithm {
  SHA1("SHA1", "http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1"),

  SHA256("SHA256", "http://www.w3.org/2000/09/xmldsig#sha256", "SHA-256"),

  SHA384("SHA384", "http://www.w3.org/2000/09/xmldsig#sha384", "SHA-384"),

  SHA512("SHA512", "http://www.w3.org/2000/09/xmldsig#sha512", "SHA-512");

  public final String digest;

  public final String name;

  public final String uri;

  DigestAlgorithm(String name, String uri, String digest) {
    this.name = name;
    this.uri = uri;
    this.digest = digest;
  }

  public static DigestAlgorithm fromURI(String uri) {
    for (DigestAlgorithm alg : values()) {
      if (alg.uri.equals(uri)) {
        return alg;
      }
    }

    return null;
  }
}
