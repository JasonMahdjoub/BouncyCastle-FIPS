/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.dvcs;

import com.distrimind.bcfips.asn1.x509.GeneralName;
import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Object;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.ASN1Sequence;
import com.distrimind.bcfips.asn1.ASN1TaggedObject;
import com.distrimind.bcfips.asn1.DERSequence;
import com.distrimind.bcfips.asn1.cmp.PKIStatusInfo;

/**
 * <pre>
 *     DVCSErrorNotice ::= SEQUENCE {
 *         transactionStatus           PKIStatusInfo ,
 *         transactionIdentifier       GeneralName OPTIONAL
 *     }
 * </pre>
 */
public class DVCSErrorNotice
    extends ASN1Object
{
    private PKIStatusInfo transactionStatus;
    private GeneralName transactionIdentifier;

    public DVCSErrorNotice(PKIStatusInfo status)
    {
        this(status, null);
    }

    public DVCSErrorNotice(PKIStatusInfo status, GeneralName transactionIdentifier)
    {
        this.transactionStatus = status;
        this.transactionIdentifier = transactionIdentifier;
    }

    private DVCSErrorNotice(ASN1Sequence seq)
    {
        this.transactionStatus = PKIStatusInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1)
        {
            this.transactionIdentifier = GeneralName.getInstance(seq.getObjectAt(1));
        }
    }

    public static DVCSErrorNotice getInstance(Object obj)
    {
        if (obj instanceof DVCSErrorNotice)
        {
            return (DVCSErrorNotice)obj;
        }
        else if (obj != null)
        {
            return new DVCSErrorNotice(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static DVCSErrorNotice getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(transactionStatus);
        if (transactionIdentifier != null)
        {
            v.add(transactionIdentifier);
        }
        return new DERSequence(v);
    }

    public String toString()
    {
        return "DVCSErrorNotice {\n" +
            "transactionStatus: " + transactionStatus + "\n" +
            (transactionIdentifier != null ? "transactionIdentifier: " + transactionIdentifier + "\n" : "") +
            "}\n";
    }


    public PKIStatusInfo getTransactionStatus()
    {
        return transactionStatus;
    }

    public GeneralName getTransactionIdentifier()
    {
        return transactionIdentifier;
    }
}
