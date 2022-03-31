package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import com.distrimind.bcfips.asn1.cms.GCMParameters;
import com.distrimind.bcfips.crypto.AuthenticationParameters;
import com.distrimind.bcfips.crypto.AuthenticationParametersWithIV;
import com.distrimind.bcfips.jcajce.spec.AEADParameterSpec;

class AuthParametersCreator<T extends AuthenticationParametersWithIV>
    implements ParametersCreator, MacParametersCreator
{
    private final AuthenticationParametersWithIV<AuthenticationParametersWithIV> baseParameters;

    AuthParametersCreator(AuthenticationParametersWithIV baseParameters)
    {
        this.baseParameters = baseParameters;
    }

    public AuthenticationParameters getBaseParameters()
    {
        return baseParameters;
    }

    public AuthenticationParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof AEADParameterSpec)
        {
            AEADParameterSpec ivTagSpec = (AEADParameterSpec)spec;

            return (AuthenticationParameters)baseParameters.withIV(ivTagSpec.getNonce()).withMACSize(ivTagSpec.getMacSizeInBits());
        }

        if (spec instanceof IvParameterSpec)
        {
            return baseParameters.withIV(((IvParameterSpec)spec).getIV());
        }

        if (GcmSpecUtil.isGcmSpec(spec))
        {
            try
            {
                GCMParameters gcm = GcmSpecUtil.extractGcmParameters(spec);
                return (AuthenticationParameters)baseParameters.withIV(gcm.getNonce()).withMACSize(gcm.getIcvLen() * 8);
            }
            catch (Exception e)
            {
                throw new InvalidAlgorithmParameterException("Cannot process GCMParameterSpec: " + e.getMessage(), e);
            }
        }

        if (spec instanceof RC2ParameterSpec)
        {
            return baseParameters.withIV(((RC2ParameterSpec)spec).getIV());
        }

        if (spec != null)
        {
            throw new InvalidAlgorithmParameterException("Unknown AlgorithmParameterSpec found: " + spec.getClass().getName());
        }

        if (forEncryption && baseParameters.getAlgorithm().requiresAlgorithmParameters())
        {
            return baseParameters.withIV(random);
        }

        return baseParameters;
    }
}
