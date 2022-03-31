/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.eac;

public class CertificationAuthorityReference
    extends CertificateHolderReference
{
    public CertificationAuthorityReference(String countryCode, String holderMnemonic, String sequenceNumber)
    {
        super(countryCode, holderMnemonic, sequenceNumber);
    }

    CertificationAuthorityReference(byte[] contents)
    {
        super(contents);
    }
}
