/*
 * Copyright (c) 2019-2025, Inversoft Inc., All Rights Reserved
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.stream.Collectors;

public class Assertion {
  public Map<String, List<String>> attributes = new HashMap<>();

  public Conditions conditions;

  public String id;

  public String issuer;

  public Subject subject;

  public Assertion() {
  }

  public Assertion(Assertion other) {
    this.attributes = other.attributes
        .entrySet()
        .stream()
        .collect(
            Collectors.toMap(
                Entry::getKey,
                entry ->  new ArrayList<>(entry.getValue())
            )
        );
    this.conditions = other.conditions == null ? null : new Conditions(other.conditions);
    this.id = other.id;
    this.issuer = other.issuer;
    this.subject = other.subject == null ? null : new Subject(other.subject);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Assertion assertion = (Assertion) o;
    return Objects.equals(attributes, assertion.attributes) &&
        Objects.equals(conditions, assertion.conditions) &&
        Objects.equals(id, assertion.id) &&
        Objects.equals(issuer, assertion.issuer) &&
        Objects.equals(subject, assertion.subject);
  }

  @Override
  public int hashCode() {
    return Objects.hash(attributes, conditions, id, issuer, subject);
  }
}
