/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.x9;

import com.distrimind.bcfips.math.ec.ECFieldElement;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.DEROctetString;

/**
 * Class for processing an FieldElement as a DER object.
 */
public class X9FieldElement
    extends ASN1Object
{
    protected ECFieldElement f;
    
    private static X9IntegerConverter converter = new X9IntegerConverter();

    public X9FieldElement(ECFieldElement f)
    {
        this.f = f;
    }

    public ECFieldElement getValue()
    {
        return f;
    }
    
    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  FieldElement ::= OCTET STRING
     * </pre>
     * <p>
     * <ol>
     * <li> if <i>q</i> is an odd prime then the field element is
     * processed as an Integer and converted to an octet string
     * according to x 9.62 4.3.1.</li>
     * <li> if <i>q</i> is 2<sup>m</sup> then the bit string
     * contained in the field element is converted into an octet
     * string with the same ordering padded at the front if necessary.
     * </li>
     * </ol>
     */
    public ASN1Primitive toASN1Primitive()
    {
        int byteCount = converter.getByteLength(f);
        byte[] paddedBigInteger = converter.integerToBytes(f.toBigInteger(), byteCount);

        return new DEROctetString(paddedBigInteger);
    }
}
