/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.cms;

import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DERSequence;

/**
 * RFC 5990 GenericHybridParameters class.
 * <pre>
 * GenericHybridParameters ::= SEQUENCE {
 *    kem  KeyEncapsulationMechanism,
 *    dem  DataEncapsulationMechanism
 * }
 *
 * KeyEncapsulationMechanism ::= AlgorithmIdentifier {{KEMAlgorithms}}
 * DataEncapsulationMechanism ::= AlgorithmIdentifier {{DEMAlgorithms}}
 * </pre>
 */
public class GenericHybridParameters
    extends ASN1Object
{
    private final AlgorithmIdentifier kem;
    private final AlgorithmIdentifier dem;

    private GenericHybridParameters(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
        }

        this.kem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        this.dem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
    }

    public static GenericHybridParameters getInstance(
        Object  o)
    {
        if (o instanceof GenericHybridParameters)
        {
            return (GenericHybridParameters)o;
        }
        else if (o != null)
        {
            return new GenericHybridParameters(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GenericHybridParameters(AlgorithmIdentifier kem, AlgorithmIdentifier dem)
    {
        this.kem = kem;
        this.dem = dem;
    }

    public AlgorithmIdentifier getDem()
    {
        return dem;
    }

    public AlgorithmIdentifier getKem()
    {
        return kem;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(kem);
        v.add(dem);

        return new DERSequence(v);
    }
}