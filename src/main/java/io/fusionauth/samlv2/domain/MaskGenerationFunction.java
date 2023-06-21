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
 * Available Mask Generation Functions for RSA OAEP.
 *
 * @author Spencer Witt
 */
public enum MaskGenerationFunction {
  MGF1_SHA1("MGF1 with SHA1", "http://www.w3.org/2009/xmlenc11#mgf1sha1", "SHA-1"),

  MGF1_SHA224("MGF1 with SHA224", "http://www.w3.org/2009/xmlenc11#mgf1sha224", "SHA-224"),

  MGF1_SHA256("MGF1 with SHA256", "http://www.w3.org/2009/xmlenc11#mgf1sha256", "SHA-256"),

  MGF1_SHA384("MGF1 with SHA384", "http://www.w3.org/2009/xmlenc11#mgf1sha384", "SHA-384"),

  MGF1_SHA512("MGF1 with SHA512", "http://www.w3.org/2009/xmlenc11#mgf1sha512", "SHA-512");

  public final String name;

  public final String digest;

  public final String uri;

  MaskGenerationFunction(String name, String uri, String digest) {
    this.name = name;
    this.uri = uri;
    this.digest = digest;
  }

  public static MaskGenerationFunction fromURI(String uri) {
    for (MaskGenerationFunction alg : values()) {
      if (alg.uri.equals(uri)) {
        return alg;
      }
    }

    return null;
  }
}
