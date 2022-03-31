package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import com.distrimind.bcfips.crypto.Parameters;

interface ParametersCreator<T extends Parameters>
{
    T createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException;
}
