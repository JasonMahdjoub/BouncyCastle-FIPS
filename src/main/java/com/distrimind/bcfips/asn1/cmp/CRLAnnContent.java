/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.cmp;

import com.distrimind.bcfips.asn1.x509.CertificateList;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.DERSequence;

public class CRLAnnContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private CRLAnnContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static CRLAnnContent getInstance(Object o)
    {
        if (o instanceof CRLAnnContent)
        {
            return (CRLAnnContent)o;
        }

        if (o != null)
        {
            return new CRLAnnContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CRLAnnContent(CertificateList crl)
    {
        this.content = new DERSequence(crl);
    }

    public CertificateList[] getCertificateLists()
    {
        CertificateList[] result = new CertificateList[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = CertificateList.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * CRLAnnContent ::= SEQUENCE OF CertificateList
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
