package com.distrimind.bcfips.pqc.addon;

import java.security.SecureRandom;

class FrodoKeyGenerationParameters
{
    private final SecureRandom random;
    private final FrodoParameters params;

    public FrodoKeyGenerationParameters(
            SecureRandom random,
            FrodoParameters frodoParameters)
    {
        this.random = random;
        this.params = frodoParameters;
    }

    public  FrodoParameters getParameters()
    {
        return params;
    }

    public SecureRandom getRandom()
    {
        return random;
    }
}
