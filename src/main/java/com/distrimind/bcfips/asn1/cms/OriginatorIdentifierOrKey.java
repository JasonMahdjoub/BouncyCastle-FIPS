/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.cms;

import com.distrimind.bcfips.asn1.ASN1Choice;
import com.distrimind.bcfips.asn1.ASN1Encodable;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.ASN1TaggedObject;
import com.distrimind.bcfips.asn1.DERTaggedObject;
import com.distrimind.bcfips.asn1.x509.SubjectKeyIdentifier;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * OriginatorIdentifierOrKey ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     subjectKeyIdentifier [0] SubjectKeyIdentifier,
 *     originatorKey [1] OriginatorPublicKey 
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 */
public class OriginatorIdentifierOrKey
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1Encodable id;

    public OriginatorIdentifierOrKey(
        IssuerAndSerialNumber id)
    {
        this.id = id;
    }

    public OriginatorIdentifierOrKey(
        SubjectKeyIdentifier id)
    {
        this.id = new DERTaggedObject(false, 0, id);
    }

    public OriginatorIdentifierOrKey(
        OriginatorPublicKey id)
    {
        this.id = new DERTaggedObject(false, 1, id);
    }

    /**
     * Return an OriginatorIdentifierOrKey object from a tagged object.
     *
     * @param o the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(
        ASN1TaggedObject    o,
        boolean             explicit)
    {
        if (!explicit)
        {
            throw new IllegalArgumentException(
                    "Can't implicitly tag OriginatorIdentifierOrKey");
        }

        return getInstance(o.getObject());
    }
    
    /**
     * Return an OriginatorIdentifierOrKey object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link OriginatorIdentifierOrKey} object
     * <li> {@link IssuerAndSerialNumber} object
     * <li> {@link com.distrimind.bcfips.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject} input formats with IssuerAndSerialNumber structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(
        Object o)
    {
        if (o == null || o instanceof OriginatorIdentifierOrKey)
        {
            return (OriginatorIdentifierOrKey)o;
        }

        if (o instanceof IssuerAndSerialNumber || o instanceof ASN1Sequence)
        {
            return new OriginatorIdentifierOrKey(IssuerAndSerialNumber.getInstance(o));
        }

        if (o instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = (ASN1TaggedObject)o;

            if (tagged.getTagNo() == 0)
            {
                return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.getInstance(tagged, false));
            }
            else if (tagged.getTagNo() == 1)
            {
                return new OriginatorIdentifierOrKey(OriginatorPublicKey.getInstance(tagged, false));
            }
        }

        throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + o.getClass().getName());
    }

    public ASN1Encodable getId()
    {
        return id;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        if (id instanceof IssuerAndSerialNumber)
        {
            return (IssuerAndSerialNumber)id;
        }

        return null;
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier()
    {
        if (id instanceof ASN1TaggedObject && ((ASN1TaggedObject)id).getTagNo() == 0)
        {
            return SubjectKeyIdentifier.getInstance((ASN1TaggedObject)id, false);
        }

        return null;
    }

    public OriginatorPublicKey getOriginatorKey()
    {
        if (id instanceof ASN1TaggedObject && ((ASN1TaggedObject)id).getTagNo() == 1)
        {
            return OriginatorPublicKey.getInstance((ASN1TaggedObject)id, false);
        }

        return null;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return id.toASN1Primitive();
    }
}
