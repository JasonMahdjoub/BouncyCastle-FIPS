/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.smime;

import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;
import com.distrimind.bcfips.asn1.pkcs.PKCSObjectIdentifiers;

public interface SMIMEAttributes
{
    ASN1ObjectIdentifier  smimeCapabilities = PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities;
    ASN1ObjectIdentifier  encrypKeyPref = PKCSObjectIdentifiers.id_aa_encrypKeyPref;
}
