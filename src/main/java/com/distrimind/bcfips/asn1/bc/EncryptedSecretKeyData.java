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
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.util.Arrays;

/**
 * <pre>
 *     EncryptedSecretKeyData ::= SEQUENCE {
 *         keyEncryptionAlgorithm AlgorithmIdentifier,
 *         encryptedKeyData OCTET STRING
 *     }
 * </pre>
 */
public class EncryptedSecretKeyData
    extends ASN1Object
{
    private final AlgorithmIdentifier keyEncryptionAlgorithm;
    private final ASN1OctetString encryptedKeyData;

    public EncryptedSecretKeyData(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] encryptedKeyData)
    {
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKeyData = new DEROctetString(Arrays.clone(encryptedKeyData));
    }

    private EncryptedSecretKeyData(ASN1Sequence seq)
    {
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.encryptedKeyData = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static EncryptedSecretKeyData getInstance(Object o)
    {
        if (o instanceof EncryptedSecretKeyData)
        {
            return (EncryptedSecretKeyData)o;
        }
        else if (o != null)
        {
            return new EncryptedSecretKeyData(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public AlgorithmIdentifier getKeyEncryptionAlgorithm()
    {
        return keyEncryptionAlgorithm;
    }

    public byte[] getEncryptedKeyData()
    {
        return Arrays.clone(encryptedKeyData.getOctets());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(keyEncryptionAlgorithm);
        v.add(encryptedKeyData);

        return new DERSequence(v);
    }
}
