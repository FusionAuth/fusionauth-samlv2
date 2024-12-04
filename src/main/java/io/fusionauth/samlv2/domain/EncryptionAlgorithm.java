/*
 * Copyright (c) 2023-2024, Inversoft Inc., All Rights Reserved
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
 * Available algorithms to encrypt SAML XML documents.
 *
 * @author Spencer Witt
 */
public enum EncryptionAlgorithm {
  /**
   * Triple DES
   */
  TripleDES("Triple DES", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "DESede/CBC/ISO10126Padding", 8),

  /**
   * AES in CBC mode with 128-bit key and 128-bit IV
   */
  AES128("AES-128", "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "AES/CBC/ISO10126Padding", 16),

  /**
   * AES in CBC mode with 192-bit key and 128-bit IV
   */
  AES192("AES-192", "http://www.w3.org/2001/04/xmlenc#aes192-cbc", "AES/CBC/ISO10126Padding", 16),

  /**
   * AES in CBC mode with 256-bit key and 128-bit IV
   */
  AES256("AES-256", "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "AES/CBC/ISO10126Padding", 16),

  /**
   * AES in GCM mode with 128-bit key, 96-bit IV, and 128-bit Authentication Tag
   */
  AES128GCM("AES128-GCM", "http://www.w3.org/2009/xmlenc11#aes128-gcm", "AES/GCM/NoPadding", 12),

  /**
   * AES in GCM mode with 192-bit key, 96-bit IV, and 128-bit Authentication Tag
   */
  AES192GCM("AES192-GCM", "http://www.w3.org/2009/xmlenc11#aes192-gcm", "AES/GCM/NoPadding", 12),

  /**
   * AES in GCM mode with 256-bit key, 96-bit IV, and 128-bit Authentication Tag
   */
  AES256GCM("AES256-GCM", "http://www.w3.org/2009/xmlenc11#aes256-gcm", "AES/GCM/NoPadding", 12);

  public final int ivLength;

  public final String name;

  public final String transformation;

  public final String uri;

  EncryptionAlgorithm(String name, String uri, String transformation, int ivLength) {
    this.name = name;
    this.uri = uri;
    this.transformation = transformation;
    this.ivLength = ivLength;
  }

  public static EncryptionAlgorithm fromURI(String uri) {
    for (EncryptionAlgorithm alg : values()) {
      if (alg.uri.equals(uri)) {
        return alg;
      }
    }

    return null;
  }
}
