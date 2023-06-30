//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.06.22 at 03:54:11 PM CDT 
//


package io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc11;

import io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc.ReferenceList;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlID;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.CollapsedStringAdapter;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for DerivedKeyType complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="DerivedKeyType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2009/xmlenc11#}KeyDerivationMethod" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2001/04/xmlenc#}ReferenceList" minOccurs="0"/>
 *         &lt;element name="DerivedKeyName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="MasterKeyName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Recipient" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *       &lt;attribute name="Type" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DerivedKeyType", propOrder = {
    "keyDerivationMethod",
    "referenceList",
    "derivedKeyName",
    "masterKeyName"
})
public class DerivedKeyType {

  @XmlElement(name = "DerivedKeyName")
  protected String derivedKeyName;

  @XmlAttribute(name = "Id")
  @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
  @XmlID
  @XmlSchemaType(name = "ID")
  protected String id;

  @XmlElement(name = "KeyDerivationMethod")
  protected KeyDerivationMethodType keyDerivationMethod;

  @XmlElement(name = "MasterKeyName")
  protected String masterKeyName;

  @XmlAttribute(name = "Recipient")
  protected String recipient;

  @XmlElement(name = "ReferenceList", namespace = "http://www.w3.org/2001/04/xmlenc#")
  protected ReferenceList referenceList;

  @XmlAttribute(name = "Type")
  @XmlSchemaType(name = "anyURI")
  protected String type;

  /**
   * Gets the value of the derivedKeyName property.
   *
   * @return possible object is {@link String }
   */
  public String getDerivedKeyName() {
    return derivedKeyName;
  }

  /**
   * Sets the value of the derivedKeyName property.
   *
   * @param value allowed object is {@link String }
   */
  public void setDerivedKeyName(String value) {
    this.derivedKeyName = value;
  }

  /**
   * Gets the value of the id property.
   *
   * @return possible object is {@link String }
   */
  public String getId() {
    return id;
  }

  /**
   * Sets the value of the id property.
   *
   * @param value allowed object is {@link String }
   */
  public void setId(String value) {
    this.id = value;
  }

  /**
   * Gets the value of the keyDerivationMethod property.
   *
   * @return possible object is {@link KeyDerivationMethodType }
   */
  public KeyDerivationMethodType getKeyDerivationMethod() {
    return keyDerivationMethod;
  }

  /**
   * Sets the value of the keyDerivationMethod property.
   *
   * @param value allowed object is {@link KeyDerivationMethodType }
   */
  public void setKeyDerivationMethod(KeyDerivationMethodType value) {
    this.keyDerivationMethod = value;
  }

  /**
   * Gets the value of the masterKeyName property.
   *
   * @return possible object is {@link String }
   */
  public String getMasterKeyName() {
    return masterKeyName;
  }

  /**
   * Sets the value of the masterKeyName property.
   *
   * @param value allowed object is {@link String }
   */
  public void setMasterKeyName(String value) {
    this.masterKeyName = value;
  }

  /**
   * Gets the value of the recipient property.
   *
   * @return possible object is {@link String }
   */
  public String getRecipient() {
    return recipient;
  }

  /**
   * Sets the value of the recipient property.
   *
   * @param value allowed object is {@link String }
   */
  public void setRecipient(String value) {
    this.recipient = value;
  }

  /**
   * Gets the value of the referenceList property.
   *
   * @return possible object is {@link ReferenceList }
   */
  public ReferenceList getReferenceList() {
    return referenceList;
  }

  /**
   * Sets the value of the referenceList property.
   *
   * @param value allowed object is {@link ReferenceList }
   */
  public void setReferenceList(ReferenceList value) {
    this.referenceList = value;
  }

  /**
   * Gets the value of the type property.
   *
   * @return possible object is {@link String }
   */
  public String getType() {
    return type;
  }

  /**
   * Sets the value of the type property.
   *
   * @param value allowed object is {@link String }
   */
  public void setType(String value) {
    this.type = value;
  }

}
