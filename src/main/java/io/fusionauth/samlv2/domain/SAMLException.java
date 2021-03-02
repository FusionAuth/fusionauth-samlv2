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
 * Thrown from the SAMLv2Service when an unrecoverable error occurs.
 *
 * @author Brian Pontarelli
 */
public class SAMLException extends Exception {
  public SAMLRequest request;

  public SAMLException() {
    super();
  }

  public SAMLException(String message) {
    super(message);
  }

  public SAMLException(String message, Throwable cause) {
    super(message, cause);
  }

  public SAMLException(String message, SAMLRequest request) {
    super(message);
    this.request = request;
  }

  public SAMLException(String message, SAMLRequest request, Throwable cause) {
    super(message, cause);
    this.request = request;
  }

  public SAMLException(Throwable cause) {
    super(cause);
  }

  protected SAMLException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
