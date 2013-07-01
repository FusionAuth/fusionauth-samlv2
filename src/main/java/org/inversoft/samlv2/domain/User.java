package org.inversoft.samlv2.domain;

/**
 * Models a single User within the system. This information is returned from the SAML IDP as NameID values.
 *
 * @author Brian Pontarelli
 */
public class User {
  public NameIDFormat format;
  public String id;
  public String qualifier;
  public String spProviderID;
  public String spQualifier;

  public User(NameIDFormat format, String id, String qualifier, String spProviderID, String spQualifier) {
    this.format = format;
    this.id = id;
    this.qualifier = qualifier;
    this.spProviderID = spProviderID;
    this.spQualifier = spQualifier;
  }
}
