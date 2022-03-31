/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.crypto.fips;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;
import com.distrimind.bcfips.crypto.internal.params.EcDomainParameters;

class EcKeyGenerationParameters
    extends KeyGenerationParameters
{
    private EcDomainParameters domainParams;

    public EcKeyGenerationParameters(
        EcDomainParameters      domainParams,
        SecureRandom            random)
    {
        super(random, domainParams.getN().bitLength());

        this.domainParams = domainParams;
    }

    public EcDomainParameters getDomainParameters()
    {
        return domainParams;
    }
}
