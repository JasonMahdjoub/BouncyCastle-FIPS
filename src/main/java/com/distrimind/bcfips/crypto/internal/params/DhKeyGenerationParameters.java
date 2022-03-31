package com.distrimind.bcfips.crypto.internal.params;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;

public class DhKeyGenerationParameters
    extends KeyGenerationParameters
{
    private DhParameters params;

    public DhKeyGenerationParameters(
        SecureRandom random,
        DhParameters params)
    {
        super(random, getStrength(params));

        this.params = params;
    }

    public DhParameters getParameters()
    {
        return params;
    }

    static int getStrength(DhParameters params)
    {
        return params.getL() != 0 ? params.getL() : params.getP().bitLength();
    }
}
