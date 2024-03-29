/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.isismtt.ocsp;

import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DEROctetString;
import com.distrimind.bcfips.asn1.DERSequence;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.util.Arrays;

/**
 * ISIS-MTT PROFILE: The responder may include this extension in a response to
 * send the hash of the requested certificate to the responder. This hash is
 * cryptographically bound to the certificate and serves as evidence that the
 * certificate is known to the responder (i.e. it has been issued and is present
 * in the directory). Hence, this extension is a means to provide a positive
 * statement of availability as described in T8.[8]. As explained in T13.[1],
 * clients may rely on this information to be able to validate signatures after
 * the expiry of the corresponding certificate. Hence, clients MUST support this
 * extension. If a positive statement of availability is to be delivered, this
 * extension syntax and OID MUST be used.
 * <pre>
 *     CertHash ::= SEQUENCE {
 *       hashAlgorithm AlgorithmIdentifier,
 *       certificateHash OCTET STRING
 *     }
 * </pre>
 */
public class CertHash
    extends ASN1Object
{

    private AlgorithmIdentifier hashAlgorithm;
    private byte[] certificateHash;

    public static CertHash getInstance(Object obj)
    {
        if (obj == null || obj instanceof CertHash)
        {
            return (CertHash)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new CertHash((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("Illegal object in getInstance: "
            + obj.getClass().getName());
    }

    /**
     * Constructor from ASN1Sequence.
     * 
     * The sequence is of type CertHash:
     * 
     * <pre>
     *     CertHash ::= SEQUENCE {
     *       hashAlgorithm AlgorithmIdentifier,
     *       certificateHash OCTET STRING
     *     }
     * </pre>
     *
     * @param seq The ASN.1 sequence.
     */
    private CertHash(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        certificateHash = DEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    /**
     * Constructor from a given details.
     *
     * @param hashAlgorithm   The hash algorithm identifier.
     * @param certificateHash The hash of the whole DER encoding of the certificate.
     */
    public CertHash(AlgorithmIdentifier hashAlgorithm, byte[] certificateHash)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.certificateHash = Arrays.clone(certificateHash);
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public byte[] getCertificateHash()
    {
        return Arrays.clone(certificateHash);
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *     CertHash ::= SEQUENCE {
     *       hashAlgorithm AlgorithmIdentifier,
     *       certificateHash OCTET STRING
     *     }
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(hashAlgorithm);
        vec.add(new DEROctetString(certificateHash));
        return new DERSequence(vec);
    }
}
