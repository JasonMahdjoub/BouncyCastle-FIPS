/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.esf;

import com.distrimind.bcfips.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;

public interface CommitmentTypeIdentifier
{
    public static final ASN1ObjectIdentifier proofOfOrigin = PKCSObjectIdentifiers.id_cti_ets_proofOfOrigin;
    public static final ASN1ObjectIdentifier proofOfReceipt = PKCSObjectIdentifiers.id_cti_ets_proofOfReceipt;
    public static final ASN1ObjectIdentifier proofOfDelivery = PKCSObjectIdentifiers.id_cti_ets_proofOfDelivery;
    public static final ASN1ObjectIdentifier proofOfSender = PKCSObjectIdentifiers.id_cti_ets_proofOfSender;
    public static final ASN1ObjectIdentifier proofOfApproval = PKCSObjectIdentifiers.id_cti_ets_proofOfApproval;
    public static final ASN1ObjectIdentifier proofOfCreation = PKCSObjectIdentifiers.id_cti_ets_proofOfCreation;
}
