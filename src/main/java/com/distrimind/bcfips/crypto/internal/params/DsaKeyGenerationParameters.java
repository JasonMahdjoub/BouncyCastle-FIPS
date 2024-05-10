/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.crypto.internal.params;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;
import com.distrimind.bcfips.crypto.internal.params.DsaParameters;

public class DsaKeyGenerationParameters
    extends KeyGenerationParameters
{
    private DsaParameters params;

    public DsaKeyGenerationParameters(
        SecureRandom    random,
        DsaParameters   params)
    {
        super(random, params.getP().bitLength() - 1);

        this.params = params;
    }

    public DsaParameters getParameters()
    {
        return params;
    }
}
