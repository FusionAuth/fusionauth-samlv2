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
 * A list of standard claims that some SAML providers return.
 *
 * @author Brian Pontarelli
 */
public enum StandardClaim {
  DateOfBirth("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth"),

  EmailAddress("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),

  FirstName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"),

  FullName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"),

  LastName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"),

  MobilePhone("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone");

  private String name;

  StandardClaim(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }
}
