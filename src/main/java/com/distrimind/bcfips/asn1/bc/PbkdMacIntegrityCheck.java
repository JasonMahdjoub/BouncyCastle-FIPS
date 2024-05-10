/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.bc;

import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DEROctetString;
import com.distrimind.bcfips.asn1.DERSequence;
import com.distrimind.bcfips.asn1.pkcs.KeyDerivationFunc;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.util.Arrays;

/**
 * <pre>
 * PbkdMacIntegrityCheck ::= SEQUENCE {
 *     macAlgorithm AlgorithmIdentifier,
 *     pbkdAlgorithm KeyDerivationFunc,
 *     mac OCTET STRING
 * }
 * </pre>
 */
public class PbkdMacIntegrityCheck
    extends ASN1Object
{
    private final AlgorithmIdentifier macAlgorithm;
    private final KeyDerivationFunc pbkdAlgorithm;
    private final ASN1OctetString mac;

    public PbkdMacIntegrityCheck(AlgorithmIdentifier macAlgorithm, KeyDerivationFunc pbkdAlgorithm, byte[] mac)
    {
        this.macAlgorithm = macAlgorithm;
        this.pbkdAlgorithm = pbkdAlgorithm;
        this.mac = new DEROctetString(Arrays.clone(mac));
    }

    private PbkdMacIntegrityCheck(ASN1Sequence seq)
    {
        this.macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.pbkdAlgorithm = KeyDerivationFunc.getInstance(seq.getObjectAt(1));
        this.mac = ASN1OctetString.getInstance(seq.getObjectAt(2));
    }

    public static PbkdMacIntegrityCheck getInstance(Object o)
    {
        if (o instanceof PbkdMacIntegrityCheck)
        {
            return (PbkdMacIntegrityCheck)o;
        }
        else if (o != null)
        {
            return new PbkdMacIntegrityCheck(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AlgorithmIdentifier getMacAlgorithm()
    {
        return macAlgorithm;
    }

    public KeyDerivationFunc getPbkdAlgorithm()
    {
        return pbkdAlgorithm;
    }

    public byte[] getMac()
    {
        return Arrays.clone(mac.getOctets());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(macAlgorithm);
        v.add(pbkdAlgorithm);
        v.add(mac);

        return new DERSequence(v);
    }
}
