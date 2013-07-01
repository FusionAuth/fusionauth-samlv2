/*
 * Copyright (c) 2013, Inversoft Inc., All Rights Reserved
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
package org.inversoft.samlv2.domain;

/**
 * Enumeration of the NameIDPolicy format values. These use uppercasing to avoid conflicts with the Java transient
 * keyword.
 *
 * @author Brian Pontarelli
 */
public enum NameIDFormat {
  /**
   * Indicates that the content of the element is in the form of an email address, specifically "addr-spec" as defined
   * in IETF RFC 2822 [RFC 2822] Section 3.4.1. An addr-spec has the form local-part@domain. Note that an addr-spec has
   * no phrase (such as a common name) before it, has no comment (text surrounded in parentheses) after it, and is not
   * surrounded by "<" and ">".
   */
  EmailAddress("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),

  /**
   * Indicates that the content of the element is the identifier of an entity that provides SAML-based services (such as
   * a SAML authority, requester, or responder) or is a participant in SAML profiles (such as a service provider
   * supporting the browser SSO profile). Such an identifier can be used in the &lt;Issuer> element to identify the
   * issuer of a SAML request, response, or assertion, or within the &lt;NameID> element to make assertions about system
   * entities that can issue SAML requests, responses, and assertions. It can also be used in other elements and
   * attributes whose purpose is to identify a system entity in various protocol exchanges.
   * <p/>
   * The syntax of such an identifier is a URI of not more than 1024 characters in length. It is RECOMMENDED that a
   * system entity use a URL containing its own domain name to identify itself.
   * <p/>
   * The NameQualifier, SPNameQualifier, and SPProvidedID attributes MUST be omitted.
   */
  Entity("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"),

  /**
   * Indicates that the content of the element is in the form of a Kerberos principal name using the format
   * name[/instance]@REALM. The syntax, format and characters allowed for the name, instance, and realm are described in
   * IETF RFC 1510 [RFC 1510].
   */
  Kerberos("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"),

  /**
   * Indicates that the content of the element is an identifier with transient semantics and SHOULD be treated as an
   * opaque and temporary value by the relying party. Transient identifier values MUST be generated in accordance with
   * the rules for SAML identifiers (see Section 1.3.4), and MUST NOT exceed a length of 256 characters.
   * <p/>
   * The NameQualifier and SPNameQualifier attributes MAY be used to signify that the identifier represents a transient
   * and temporary pair-wise identifier. In such a case, they MAY be omitted in accordance with the rules specified in
   * Section 8.3.7.
   */
  Transient("urn:oasis:names:tc:SAML:1.1:nameid-format:transient"),

  /**
   * Indicates that the content of the element is a persistent opaque identifier for a principal that is specific to an
   * identity provider and a service provider or affiliation of service providers. Persistent name identifiers generated
   * by identity providers MUST be constructed using pseudo-random values that have no discernible correspondence with
   * the subject's actual identifier (for example, username). The intent is to create a non-public, pair-wise pseudonym
   * to prevent the discovery of the subject's identity or activities. Persistent name identifier values MUST NOT exceed
   * a length of 256 characters.
   * <p/>
   * The element's NameQualifier attribute, if present, MUST contain the unique identifier of the identity provider that
   * generated the identifier (see Section 8.3.6). It MAY be omitted if the value can be derived from the context of the
   * message containing the element, such as the issuer of a protocol message or an assertion containing the identifier
   * in its subject. Note that a different system entity might later issue its own protocol message or assertion
   * containing the identifier; the NameQualifier attribute does not change in this case, but MUST continue to identify
   * the entity that originally created the identifier (and MUST NOT be omitted in such a case).
   * <p/>
   * The element's SPNameQualifier attribute, if present, MUST contain the unique identifier of the service provider or
   * affiliation of providers for whom the identifier was generated (see Section 8.3.6). It MAY be omitted if the
   * element is contained in a message intended only for consumption directly by the service provider, and the value
   * would be the unique identifier of that service provider.
   * <p/>
   * The element's SPProvidedID attribute MUST contain the alternative identifier of the principal most recently set by
   * the service provider or affiliation, if any (see Section 3.6). If no such identifier has been established, then the
   * attribute MUST be omitted.
   * <p/>
   * Persistent identifiers are intended as a privacy protection mechanism; as such they MUST NOT be shared in clear
   * text with providers other than the providers that have established the shared identifier. Furthermore, they MUST
   * NOT appear in log files or similar locations without appropriate controls and protections. Deployments without such
   * requirements are free to use other kinds of identifiers in their SAML exchanges, but MUST NOT overload this format
   * with persistent but non-opaque values.
   * <p/>
   * Note also that while persistent identifiers are typically used to reflect an account linking relationship between a
   * pair of providers, a service provider is not obligated to recognize or make use of the long term nature of the
   * persistent identifier or establish such a link. Such a "one-sided" relationship is not discernibly different and
   * does not affect the behavior of the identity provider or any processing rules specific to persistent identifiers in
   * the protocols defined in this specification.
   * <p/>
   * Finally, note that the NameQualifier and SPNameQualifier attributes indicate directionality of creation, but not of
   * use. If a persistent identifier is created by a particular identity provider, the NameQualifier attribute value is
   * permanently established at that time. If a service provider that receives such an identifier takes on the role of
   * an identity provider and issues its own assertion containing that identifier, the NameQualifier attribute value
   * does not change (and would of course not be omitted). It might alternatively choose to create its own persistent
   * identifier to represent the principal and link the two values. This is a deployment decision.
   */
  Persistent("urn:oasis:names:tc:SAML:1.1:nameid-format:persistent"),

  /**
   * The interpretation of the content of the element is left to individual implementations.
   */
  Unspecified("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),

  /**
   * Indicates that the content of the element is a Windows domain qualified name. A Windows domain qualified user name
   * is a string of the form "DomainName\UserName". The domain name and "\" separator MAY be omitted.
   */
  WindowsDomain("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"),

  /**
   * Indicates that the content of the element is in the form specified for the contents of the &lt;ds:X509SubjectName>
   * element in the XML Signature Recommendation [XMLSig]. Implementors should note that the XML Signature specification
   * specifies encoding rules for X.509 subject names that differ from the rules given in IETF RFC 2253 [RFC 2253].
   */
  X509("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
  /**
   * The SAML String.
   */
  private final String samlFormat;

  private NameIDFormat(String samlFormat) {
    this.samlFormat = samlFormat;
  }

  /**
   * Locates the NameIDFOrmat using the given SAML String. This is the value from the StatusCode element's value.
   *
   * @param samlFormat The SAML string.
   * @return The NameIDFormat enum instance.
   * @throws IllegalArgumentException If the samlFormat String is not a valid name ID format.
   */
  public static NameIDFormat fromSAMLFormat(String samlFormat) {
    if (samlFormat == null) {
      return null;
    }

    for (NameIDFormat nameID : NameIDFormat.values()) {
      if (nameID.toSAMLFormat().equals(samlFormat)) {
        return nameID;
      }
    }

    throw new IllegalArgumentException("Invalid SAML v2.0 Name ID format [" + samlFormat + "]");
  }

  public String toSAMLFormat() {
    return samlFormat;
  }
}
