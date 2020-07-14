package com.distrimind.bcfips.jcajce.provider;

import java.security.NoSuchAlgorithmException;

import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;

class GuardedEngineCreator
    implements EngineCreator
{
    private final EngineCreator creator;

    GuardedEngineCreator(EngineCreator creator)
    {
        this.creator = creator;
    }

    public Object createInstance(Object constructorParameter)
        throws NoSuchAlgorithmException
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        return creator.createInstance(constructorParameter);
    }
}
