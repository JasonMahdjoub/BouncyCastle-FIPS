package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.ParametersWithIV;

class IvParametersCreator<T extends ParametersWithIV>
    implements ParametersCreator
{
    private final ParametersWithIV baseParameters;

    IvParametersCreator(ParametersWithIV baseParameters)
    {
        this.baseParameters = baseParameters;
    }

    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof IvParameterSpec)
        {
            return baseParameters.withIV(((IvParameterSpec)spec).getIV());
        }

        if (forEncryption && baseParameters.getAlgorithm().requiresAlgorithmParameters())
        {
            return baseParameters.withIV(random);
        }

        return baseParameters;
    }
}
