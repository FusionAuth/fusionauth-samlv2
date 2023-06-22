//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.06.22 at 03:54:11 PM CDT 
//


package io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc11;

import io.fusionauth.samlv2.domain.jaxb.w3c.xmldsig.DigestMethodType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.HexBinaryAdapter;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for ConcatKDFParamsType complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="ConcatKDFParamsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2000/09/xmldsig#}DigestMethod"/>
 *       &lt;/sequence>
 *       &lt;attribute name="AlgorithmID" type="{http://www.w3.org/2001/XMLSchema}hexBinary" />
 *       &lt;attribute name="PartyUInfo" type="{http://www.w3.org/2001/XMLSchema}hexBinary" />
 *       &lt;attribute name="PartyVInfo" type="{http://www.w3.org/2001/XMLSchema}hexBinary" />
 *       &lt;attribute name="SuppPubInfo" type="{http://www.w3.org/2001/XMLSchema}hexBinary" />
 *       &lt;attribute name="SuppPrivInfo" type="{http://www.w3.org/2001/XMLSchema}hexBinary" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ConcatKDFParamsType", propOrder = {
    "digestMethod"
})
public class ConcatKDFParamsType {

  @XmlAttribute(name = "AlgorithmID")
  @XmlJavaTypeAdapter(HexBinaryAdapter.class)
  @XmlSchemaType(name = "hexBinary")
  protected byte[] algorithmID;

  @XmlElement(name = "DigestMethod", namespace = "http://www.w3.org/2000/09/xmldsig#", required = true)
  protected DigestMethodType digestMethod;

  @XmlAttribute(name = "PartyUInfo")
  @XmlJavaTypeAdapter(HexBinaryAdapter.class)
  @XmlSchemaType(name = "hexBinary")
  protected byte[] partyUInfo;

  @XmlAttribute(name = "PartyVInfo")
  @XmlJavaTypeAdapter(HexBinaryAdapter.class)
  @XmlSchemaType(name = "hexBinary")
  protected byte[] partyVInfo;

  @XmlAttribute(name = "SuppPrivInfo")
  @XmlJavaTypeAdapter(HexBinaryAdapter.class)
  @XmlSchemaType(name = "hexBinary")
  protected byte[] suppPrivInfo;

  @XmlAttribute(name = "SuppPubInfo")
  @XmlJavaTypeAdapter(HexBinaryAdapter.class)
  @XmlSchemaType(name = "hexBinary")
  protected byte[] suppPubInfo;

  /**
   * Gets the value of the algorithmID property.
   *
   * @return possible object is {@link String }
   */
  public byte[] getAlgorithmID() {
    return algorithmID;
  }

  /**
   * Sets the value of the algorithmID property.
   *
   * @param value allowed object is {@link String }
   */
  public void setAlgorithmID(byte[] value) {
    this.algorithmID = value;
  }

  /**
   * Gets the value of the digestMethod property.
   *
   * @return possible object is {@link DigestMethodType }
   */
  public DigestMethodType getDigestMethod() {
    return digestMethod;
  }

  /**
   * Sets the value of the digestMethod property.
   *
   * @param value allowed object is {@link DigestMethodType }
   */
  public void setDigestMethod(DigestMethodType value) {
    this.digestMethod = value;
  }

  /**
   * Gets the value of the partyUInfo property.
   *
   * @return possible object is {@link String }
   */
  public byte[] getPartyUInfo() {
    return partyUInfo;
  }

  /**
   * Sets the value of the partyUInfo property.
   *
   * @param value allowed object is {@link String }
   */
  public void setPartyUInfo(byte[] value) {
    this.partyUInfo = value;
  }

  /**
   * Gets the value of the partyVInfo property.
   *
   * @return possible object is {@link String }
   */
  public byte[] getPartyVInfo() {
    return partyVInfo;
  }

  /**
   * Sets the value of the partyVInfo property.
   *
   * @param value allowed object is {@link String }
   */
  public void setPartyVInfo(byte[] value) {
    this.partyVInfo = value;
  }

  /**
   * Gets the value of the suppPrivInfo property.
   *
   * @return possible object is {@link String }
   */
  public byte[] getSuppPrivInfo() {
    return suppPrivInfo;
  }

  /**
   * Sets the value of the suppPrivInfo property.
   *
   * @param value allowed object is {@link String }
   */
  public void setSuppPrivInfo(byte[] value) {
    this.suppPrivInfo = value;
  }

  /**
   * Gets the value of the suppPubInfo property.
   *
   * @return possible object is {@link String }
   */
  public byte[] getSuppPubInfo() {
    return suppPubInfo;
  }

  /**
   * Sets the value of the suppPubInfo property.
   *
   * @param value allowed object is {@link String }
   */
  public void setSuppPubInfo(byte[] value) {
    this.suppPubInfo = value;
  }

}
