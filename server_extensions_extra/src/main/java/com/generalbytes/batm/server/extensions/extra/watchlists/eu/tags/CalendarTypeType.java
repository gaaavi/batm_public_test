//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.12.07 at 11:07:14 AM CET 
//


package com.generalbytes.batm.server.extensions.extra.watchlists.eu.tags;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CalendarTypeType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="CalendarTypeType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="GREGORIAN"/>
 *     &lt;enumeration value="ISLAMIC"/>
 *     &lt;enumeration value="BUDDHIST"/>
 *     &lt;enumeration value="COPTIC"/>
 *     &lt;enumeration value="ETHIOPIC"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "CalendarTypeType")
@XmlEnum
public enum CalendarTypeType {

    GREGORIAN,
    ISLAMIC,
    BUDDHIST,
    COPTIC,
    ETHIOPIC;

    public String value() {
        return name();
    }

    public static CalendarTypeType fromValue(String v) {
        return valueOf(v);
    }

}
