//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 in JDK 6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2013.06.27 at 01:49:11 PM MDT 
//


package org.inversoft.samlv2.domain.jaxb.oasis.metadata;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import org.inversoft.samlv2.domain.jaxb.oasis.assertion.AttributeType;


/**
 * <p>Java class for IDPSSODescriptorType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IDPSSODescriptorType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:oasis:names:tc:SAML:2.0:metadata}SSODescriptorType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService" maxOccurs="unbounded"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}NameIDMappingService" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AssertionIDRequestService" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AttributeProfile" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}Attribute" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="WantAuthnRequestsSigned" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;anyAttribute processContents='lax' namespace='##other'/>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IDPSSODescriptorType", propOrder = {
    "singleSignOnService",
    "nameIDMappingService",
    "assertionIDRequestService",
    "attributeProfile",
    "attribute"
})
public class IDPSSODescriptorType
    extends SSODescriptorType
{

    @XmlElement(name = "SingleSignOnService", required = true)
    protected List<EndpointType> singleSignOnService;
    @XmlElement(name = "NameIDMappingService")
    protected List<EndpointType> nameIDMappingService;
    @XmlElement(name = "AssertionIDRequestService")
    protected List<EndpointType> assertionIDRequestService;
    @XmlElement(name = "AttributeProfile")
    @XmlSchemaType(name = "anyURI")
    protected List<String> attributeProfile;
    @XmlElement(name = "Attribute", namespace = "urn:oasis:names:tc:SAML:2.0:assertion")
    protected List<AttributeType> attribute;
    @XmlAttribute(name = "WantAuthnRequestsSigned")
    protected Boolean wantAuthnRequestsSigned;

    /**
     * Gets the value of the singleSignOnService property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the singleSignOnService property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSingleSignOnService().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link EndpointType }
     * 
     * 
     */
    public List<EndpointType> getSingleSignOnService() {
        if (singleSignOnService == null) {
            singleSignOnService = new ArrayList<EndpointType>();
        }
        return this.singleSignOnService;
    }

    /**
     * Gets the value of the nameIDMappingService property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the nameIDMappingService property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getNameIDMappingService().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link EndpointType }
     * 
     * 
     */
    public List<EndpointType> getNameIDMappingService() {
        if (nameIDMappingService == null) {
            nameIDMappingService = new ArrayList<EndpointType>();
        }
        return this.nameIDMappingService;
    }

    /**
     * Gets the value of the assertionIDRequestService property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the assertionIDRequestService property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAssertionIDRequestService().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link EndpointType }
     * 
     * 
     */
    public List<EndpointType> getAssertionIDRequestService() {
        if (assertionIDRequestService == null) {
            assertionIDRequestService = new ArrayList<EndpointType>();
        }
        return this.assertionIDRequestService;
    }

    /**
     * Gets the value of the attributeProfile property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the attributeProfile property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAttributeProfile().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getAttributeProfile() {
        if (attributeProfile == null) {
            attributeProfile = new ArrayList<String>();
        }
        return this.attributeProfile;
    }

    /**
     * Gets the value of the attribute property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the attribute property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAttribute().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link AttributeType }
     * 
     * 
     */
    public List<AttributeType> getAttribute() {
        if (attribute == null) {
            attribute = new ArrayList<AttributeType>();
        }
        return this.attribute;
    }

    /**
     * Gets the value of the wantAuthnRequestsSigned property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isWantAuthnRequestsSigned() {
        return wantAuthnRequestsSigned;
    }

    /**
     * Sets the value of the wantAuthnRequestsSigned property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setWantAuthnRequestsSigned(Boolean value) {
        this.wantAuthnRequestsSigned = value;
    }

}
