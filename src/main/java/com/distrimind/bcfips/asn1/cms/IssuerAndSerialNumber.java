/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.cms;

import java.math.BigInteger;

import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Integer;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DERSequence;
import com.distrimind.bcfips.asn1.x500.X500Name;
import com.distrimind.bcfips.asn1.x509.Certificate;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-10.2.4">RFC 5652</a>: IssuerAndSerialNumber object.
 * <p>
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *     issuer Name,
 *     serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER  -- See RFC 5280
 * </pre>
 */
public class IssuerAndSerialNumber
    extends ASN1Object
{
    private X500Name    name;
    private ASN1Integer  serialNumber;

    /**
     * Return an IssuerAndSerialNumber object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link IssuerAndSerialNumber} object
     * <li> {@link com.distrimind.bcfips.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with IssuerAndSerialNumber structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static IssuerAndSerialNumber getInstance(
        Object  obj)
    {
        if (obj instanceof IssuerAndSerialNumber)
        {
            return (IssuerAndSerialNumber)obj;
        }
        else if (obj != null)
        {
            return new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private IssuerAndSerialNumber(
        ASN1Sequence    seq)
    {
        this.name = X500Name.getInstance(seq.getObjectAt(0));
        this.serialNumber = (ASN1Integer)seq.getObjectAt(1);
    }

    public IssuerAndSerialNumber(
        Certificate certificate)
    {
        this.name = certificate.getIssuer();
        this.serialNumber = certificate.getSerialNumber();
    }

    public IssuerAndSerialNumber(
        X500Name name,
        BigInteger  serialNumber)
    {
        this.name = name;
        this.serialNumber = new ASN1Integer(serialNumber);
    }

    public X500Name getName()
    {
        return name;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(name);
        v.add(serialNumber);

        return new DERSequence(v);
    }
}
