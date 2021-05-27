/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.x9;

import java.math.BigInteger;

import com.distrimind.bcfips.math.ec.ECAlgorithms;
import com.distrimind.bcfips.math.ec.ECCurve;
import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Integer;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;
import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DERBitString;
import com.distrimind.bcfips.asn1.DERSequence;

/**
 * ASN.1 def for Elliptic-Curve Curve structure. See
 * X9.62, for further details.
 */
public class X9Curve
    extends ASN1Object
    implements X9ObjectIdentifiers
{
    private ECCurve curve;
    private byte[]      seed;
    private ASN1ObjectIdentifier fieldIdentifier = null;

    public X9Curve(
        ECCurve     curve)
    {
        this(curve, null);
    }

    public X9Curve(
        ECCurve     curve,
        byte[]      seed)
    {
        this.curve = curve;
        this.seed = Arrays.clone(seed);
        setFieldIdentifier();
    }

    public X9Curve(
        X9FieldID     fieldID,
        BigInteger    order,
        BigInteger    cofactor,
        ASN1Sequence  seq)
    {   
        fieldIdentifier = fieldID.getIdentifier();
        if (fieldIdentifier.equals(prime_field))
        {   
            BigInteger p = ((ASN1Integer)fieldID.getParameters()).getValue();
            BigInteger A = new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());      
            BigInteger B = new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());      
            curve = new ECCurve.Fp(p, A, B, order, cofactor);
        }
        else if (fieldIdentifier.equals(characteristic_two_field))
        {
            // Characteristic two field
            ASN1Sequence parameters = ASN1Sequence.getInstance(fieldID.getParameters());
            int m = ((ASN1Integer)parameters.getObjectAt(0)).getValue().
                intValue();
            ASN1ObjectIdentifier representation
                = (ASN1ObjectIdentifier)parameters.getObjectAt(1);

            int k1 = 0;
            int k2 = 0;
            int k3 = 0;

            if (representation.equals(tpBasis))
            {
                // Trinomial basis representation
                k1 = ASN1Integer.getInstance(parameters.getObjectAt(2)).getValue().intValue();
            }   
            else if (representation.equals(ppBasis))
            {
                // Pentanomial basis representation
                ASN1Sequence pentanomial = ASN1Sequence.getInstance(parameters.getObjectAt(2));
                k1 = ASN1Integer.getInstance(pentanomial.getObjectAt(0)).getValue().intValue();
                k2 = ASN1Integer.getInstance(pentanomial.getObjectAt(1)).getValue().intValue();
                k3 = ASN1Integer.getInstance(pentanomial.getObjectAt(2)).getValue().intValue();
            }   
            else
            {
                throw new IllegalArgumentException("This type of EC basis is not implemented");
            }   
            BigInteger A = new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());      
            BigInteger B = new BigInteger(1, ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());      
            curve = new ECCurve.F2m(m, k1, k2, k3, A, B, order, cofactor);
        }   
        else
        {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        }   

        if (seq.size() == 3)
        {
            seed = Arrays.clone(((DERBitString)seq.getObjectAt(2)).getBytes());
        }   
    }   

    private void setFieldIdentifier()
    {
        if (ECAlgorithms.isFpCurve(curve))
        {
            fieldIdentifier = prime_field;
        }
        else if (ECAlgorithms.isF2mCurve(curve))
        {
            fieldIdentifier = characteristic_two_field;
        }
        else
        {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        }
    }

    public ECCurve  getCurve()
    {
        return curve;
    }

    public byte[]   getSeed()
    {
        return Arrays.clone(seed);
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  Curve ::= SEQUENCE {
     *      a               FieldElement,
     *      b               FieldElement,
     *      seed            BIT STRING      OPTIONAL
     *  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (fieldIdentifier.equals(prime_field)) 
        { 
            v.add(new X9FieldElement(curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(curve.getB()).toASN1Primitive());
        } 
        else if (fieldIdentifier.equals(characteristic_two_field)) 
        {
            v.add(new X9FieldElement(curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(curve.getB()).toASN1Primitive());
        }

        if (seed != null)
        {
            v.add(new DERBitString(seed));
        }

        return new DERSequence(v);
    }
}
