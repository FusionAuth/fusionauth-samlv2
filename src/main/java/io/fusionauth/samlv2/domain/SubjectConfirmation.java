/*
 * Copyright (c) 2013-2025, Inversoft Inc., All Rights Reserved
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

import java.time.ZonedDateTime;
import java.util.Objects;

/**
 * @author Brian Pontarelli
 */
public class SubjectConfirmation {
  public String address;

  public String inResponseTo;

  public ConfirmationMethod method;

  public ZonedDateTime notOnOrAfter;

  public String recipient;

  public SubjectConfirmation() {
  }

  public SubjectConfirmation(SubjectConfirmation subjectConfirmation) {
    this.address = subjectConfirmation.address;
    this.inResponseTo = subjectConfirmation.inResponseTo;
    this.method = subjectConfirmation.method;
    this.notOnOrAfter = subjectConfirmation.notOnOrAfter;
    this.recipient = subjectConfirmation.recipient;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SubjectConfirmation that = (SubjectConfirmation) o;
    return Objects.equals(address, that.address) &&
        Objects.equals(inResponseTo, that.inResponseTo) &&
        method == that.method &&
        Objects.equals(notOnOrAfter, that.notOnOrAfter) &&
        Objects.equals(recipient, that.recipient);
  }

  @Override
  public int hashCode() {
    return Objects.hash(address, inResponseTo, method, notOnOrAfter, recipient);
  }
}
