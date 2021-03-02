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
 * Thrown from the SAMLv2Service when the caller indicated the signature must be verified and a signature was not
 * found.
 *
 * @author Daniel DeGroff
 */
public class SignatureNotFoundException extends SAMLException {
  public SignatureNotFoundException() {
    super();
  }

  public SignatureNotFoundException(String message) {
    super(message);
  }

  public SignatureNotFoundException(String message, SAMLRequest request) {
    super(message);
    this.request = request;
  }

  public SignatureNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }

  public SignatureNotFoundException(Throwable cause) {
    super(cause);
  }

  protected SignatureNotFoundException(String message, Throwable cause, boolean enableSuppression,
                                       boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
