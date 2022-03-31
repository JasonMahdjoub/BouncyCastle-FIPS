/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.misc;

import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DEROctetString;
import com.distrimind.bcfips.asn1.DERSequence;

public class IDEACBCPar
    extends ASN1Object
{
    ASN1OctetString  iv;

    public static IDEACBCPar getInstance(
        Object  o)
    {
        if (o instanceof IDEACBCPar)
        {
            return (IDEACBCPar)o;
        }
        else if (o != null)
        {
            return new IDEACBCPar(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public IDEACBCPar(
        byte[]  iv)
    {
        this.iv = new DEROctetString(iv);
    }

    private IDEACBCPar(
        ASN1Sequence  seq)
    {
        if (seq.size() == 1)
        {
            iv = (ASN1OctetString)seq.getObjectAt(0);
        }
        else
        {
            iv = null;
        }
    }

    public byte[] getIV()
    {
        if (iv != null)
        {
            return Arrays.clone(iv.getOctets());
        }
        else
        {
            return null;
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * IDEA-CBCPar ::= SEQUENCE {
     *                      iv    OCTET STRING OPTIONAL -- exactly 8 octets
     *                  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        if (iv != null)
        {
            v.add(iv);
        }

        return new DERSequence(v);
    }
}
