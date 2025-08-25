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

import java.util.List;
import java.util.Objects;

public class Subject {
  public List<NameID> nameIDs;

  public SubjectConfirmation subjectConfirmation;

  public Subject() {
  }

  public Subject(Subject other) {
    this.nameIDs = other.nameIDs == null ? null : other.nameIDs.stream().map(NameID::new).toList();
    this.subjectConfirmation = other.subjectConfirmation == null ? null : new SubjectConfirmation(other.subjectConfirmation);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Subject subject = (Subject) o;
    return Objects.equals(nameIDs, subject.nameIDs) &&
        Objects.equals(subjectConfirmation, subject.subjectConfirmation);
  }

  @Override
  public int hashCode() {
    return Objects.hash(nameIDs, subjectConfirmation);
  }
}
