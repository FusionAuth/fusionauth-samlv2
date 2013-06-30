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
  Transient("urn:oasis:names:tc:SAML:1.1:nameid-format:transient"),

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
  private final String samlFormat;

  private NameIDFormat(String samlFormat) {
    this.samlFormat = samlFormat;
  }

  public String toSAMLFormat() {
    return samlFormat;
  }
}
