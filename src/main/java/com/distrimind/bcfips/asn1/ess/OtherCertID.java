/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.ess;

import com.distrimind.bcfips.asn1.oiw.OIWObjectIdentifiers;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.asn1.x509.DigestInfo;
import com.distrimind.bcfips.asn1.x509.IssuerSerial;
import com.distrimind.bcfips.asn1.ASN1Encodable;
import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DERSequence;

public class OtherCertID
    extends ASN1Object
{
    private ASN1Encodable otherCertHash;
    private IssuerSerial issuerSerial;

    public static OtherCertID getInstance(Object o)
    {
        if (o instanceof OtherCertID)
        {
            return (OtherCertID) o;
        }
        else if (o != null)
        {
            return new OtherCertID(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private OtherCertID(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        if (seq.getObjectAt(0).toASN1Primitive() instanceof ASN1OctetString)
        {
            otherCertHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        }
        else
        {
            otherCertHash = DigestInfo.getInstance(seq.getObjectAt(0));

        }

        if (seq.size() > 1)
        {
            issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
        }
    }

    public OtherCertID(
        AlgorithmIdentifier algId,
        byte[]               digest)
    {
        this.otherCertHash = new DigestInfo(algId, digest);
    }

    public OtherCertID(
        AlgorithmIdentifier  algId,
        byte[]               digest,
        IssuerSerial    issuerSerial)
    {
        this.otherCertHash = new DigestInfo(algId, digest);
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getAlgorithmHash()
    {
        if (otherCertHash.toASN1Primitive() instanceof ASN1OctetString)
        {
            // SHA-1
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
        }
        else
        {
            return DigestInfo.getInstance(otherCertHash).getAlgorithmId();
        }
    }

    public byte[] getCertHash()
    {
        if (otherCertHash.toASN1Primitive() instanceof ASN1OctetString)
        {
            // SHA-1
            return ((ASN1OctetString)otherCertHash.toASN1Primitive()).getOctets();
        }
        else
        {
            return DigestInfo.getInstance(otherCertHash).getDigest();
        }
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * OtherCertID ::= SEQUENCE {
     *     otherCertHash    OtherHash,
     *     issuerSerial     IssuerSerial OPTIONAL }
     *
     * OtherHash ::= CHOICE {
     *     sha1Hash     OCTET STRING,
     *     otherHash    OtherHashAlgAndValue }
     *
     * OtherHashAlgAndValue ::= SEQUENCE {
     *     hashAlgorithm    AlgorithmIdentifier,
     *     hashValue        OCTET STRING }
     *
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(otherCertHash);

        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }
}
