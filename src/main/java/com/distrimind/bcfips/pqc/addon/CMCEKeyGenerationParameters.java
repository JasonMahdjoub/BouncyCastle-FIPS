package com.distrimind.bcfips.pqc.addon;

import java.security.SecureRandom;

class CMCEKeyGenerationParameters
{
    private final SecureRandom random;
    private final CMCEParameters params;

    public CMCEKeyGenerationParameters(
        SecureRandom random,
        CMCEParameters cmceParams)
    {
        this.random = random;
        this.params = cmceParams;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }

    public SecureRandom getRandom()
    {
        return random;
    }
}
