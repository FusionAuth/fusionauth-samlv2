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
 * Location for the encrypted symmetric key in relation to the {@code <EncryptedData>} element.
 *
 * @author Spencer Witt
 */
public enum KeyLocation {
  /**
   * The {@code EncryptedKey} element will be wrapped in a {@code KeyInfo} element and added inside the
   * {@code EncryptedData}
   */
  Child,

  /**
   * The {@code EncryptedKey} element will be added to the document as a sibling of {@code EncryptedData}
   */
  Sibling
}
