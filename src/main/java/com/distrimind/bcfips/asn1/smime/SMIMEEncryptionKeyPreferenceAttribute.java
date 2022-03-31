/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.smime;

import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.DERSet;
import com.distrimind.bcfips.asn1.DERTaggedObject;
import com.distrimind.bcfips.asn1.cms.Attribute;
import com.distrimind.bcfips.asn1.cms.IssuerAndSerialNumber;
import com.distrimind.bcfips.asn1.cms.RecipientKeyIdentifier;

/**
 * The SMIMEEncryptionKeyPreference object.
 * <pre>
 * SMIMEEncryptionKeyPreference ::= CHOICE {
 *     issuerAndSerialNumber   [0] IssuerAndSerialNumber,
 *     receipentKeyId          [1] RecipientKeyIdentifier,
 *     subjectAltKeyIdentifier [2] SubjectKeyIdentifier
 * }
 * </pre>
 */
public class SMIMEEncryptionKeyPreferenceAttribute
    extends Attribute
{
    public SMIMEEncryptionKeyPreferenceAttribute(
        IssuerAndSerialNumber issAndSer)
    {
        super(SMIMEAttributes.encrypKeyPref,
                new DERSet(new DERTaggedObject(false, 0, issAndSer)));
    }
    
    public SMIMEEncryptionKeyPreferenceAttribute(
        RecipientKeyIdentifier rKeyId)
    {

        super(SMIMEAttributes.encrypKeyPref, 
                    new DERSet(new DERTaggedObject(false, 1, rKeyId)));
    }
    
    /**
     * @param sKeyId the subjectKeyIdentifier value (normally the X.509 one)
     */
    public SMIMEEncryptionKeyPreferenceAttribute(
        ASN1OctetString sKeyId)
    {

        super(SMIMEAttributes.encrypKeyPref,
                    new DERSet(new DERTaggedObject(false, 2, sKeyId)));
    }
}
