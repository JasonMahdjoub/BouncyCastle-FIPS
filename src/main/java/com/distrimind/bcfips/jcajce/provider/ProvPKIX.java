package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

class ProvPKIX
    extends AsymmetricAlgorithmProvider
{
    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("CertPathValidator.PKIX", "com.distrimind.bcfips.jce.provider.PKIXCertPathValidatorSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new PKIXCertPathValidatorSpi(provider);
            }
        });
        provider.addAlgorithmImplementation("CertPathBuilder.PKIX", "com.distrimind.bcfips.jce.provider.PKIXCertPathBuilderSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new PKIXCertPathBuilderSpi(provider);
            }
        });
        provider.addAlgorithmImplementation("CertStore.COLLECTION", "com.distrimind.bcfips.jce.provider.CertStoreCollectionSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
            {
                try
                {
                    return new CertStoreCollectionSpi((java.security.cert.CertStoreParameters)constructorParameter);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new NoSuchAlgorithmException("Unable to construct CertStore implementation: " + e.getMessage(), e);
                }
            }
        });
    }
}
