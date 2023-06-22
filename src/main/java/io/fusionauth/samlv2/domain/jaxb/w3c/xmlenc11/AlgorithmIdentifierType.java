//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.06.22 at 03:54:11 PM CDT 
//


package io.fusionauth.samlv2.domain.jaxb.w3c.xmlenc11;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AlgorithmIdentifierType complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="AlgorithmIdentifierType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Parameters" type="{http://www.w3.org/2001/XMLSchema}anyType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Algorithm" use="required" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AlgorithmIdentifierType", propOrder = {
    "parameters"
})
@XmlSeeAlso({
    MGFType.class,
    PRFAlgorithmIdentifierType.class
})
public class AlgorithmIdentifierType {

  @XmlAttribute(name = "Algorithm", required = true)
  @XmlSchemaType(name = "anyURI")
  protected String algorithm;

  @XmlElement(name = "Parameters")
  protected Object parameters;

  /**
   * Gets the value of the algorithm property.
   *
   * @return possible object is {@link String }
   */
  public String getAlgorithm() {
    return algorithm;
  }

  /**
   * Sets the value of the algorithm property.
   *
   * @param value allowed object is {@link String }
   */
  public void setAlgorithm(String value) {
    this.algorithm = value;
  }

  /**
   * Gets the value of the parameters property.
   *
   * @return possible object is {@link Object }
   */
  public Object getParameters() {
    return parameters;
  }

  /**
   * Sets the value of the parameters property.
   *
   * @param value allowed object is {@link Object }
   */
  public void setParameters(Object value) {
    this.parameters = value;
  }

}
