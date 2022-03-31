package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import com.distrimind.bcfips.crypto.AuthenticationParameters;

interface MacParametersCreator<T extends AuthenticationParameters>
{
    T getBaseParameters();

    T createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException;
}
