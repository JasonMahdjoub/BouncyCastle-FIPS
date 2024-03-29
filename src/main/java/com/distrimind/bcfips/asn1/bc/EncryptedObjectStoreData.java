/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.bc;

import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DEROctetString;
import com.distrimind.bcfips.asn1.DERSequence;

/**
 * <pre>
 * EncryptedObjectStoreData ::= SEQUENCE {
 *     encryptionAlgorithm AlgorithmIdentifier
 *     encryptedContent OCTET STRING
 * }
 * </pre>
 */
public class EncryptedObjectStoreData
    extends ASN1Object
{
    private final AlgorithmIdentifier encryptionAlgorithm;
    private final ASN1OctetString encryptedContent;

    public EncryptedObjectStoreData(AlgorithmIdentifier encryptionAlgorithm, byte[] encryptedContent)
    {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.encryptedContent = new DEROctetString(encryptedContent);
    }

    private EncryptedObjectStoreData(ASN1Sequence seq)
    {
        this.encryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.encryptedContent = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static EncryptedObjectStoreData getInstance(Object o)
    {
        if (o instanceof EncryptedObjectStoreData)
        {
            return (EncryptedObjectStoreData)o;
        }
        else if (o != null)
        {
            return new EncryptedObjectStoreData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1OctetString getEncryptedContent()
    {
        return encryptedContent;
    }

    public AlgorithmIdentifier getEncryptionAlgorithm()
    {
        return encryptionAlgorithm;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(encryptionAlgorithm);
        v.add(encryptedContent);

        return new DERSequence(v);
    }
}