package org.bouncycastle.jcajce.provider;


import java.security.SecureRandom;
import java.security.SecureRandomSpi;

class ProvRandom
    extends AsymmetricAlgorithmProvider
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider" + ".random.";

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("SecureRandom.DEFAULT", PREFIX + "DefSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                final SecureRandom random = provider.getDefaultSecureRandom();

                return new SecureRandomSpi()
                {
                    @Override
                    protected void engineSetSeed(byte[] bytes)
                    {
                        random.setSeed(bytes);
                    }

                    @Override
                    protected void engineNextBytes(byte[] bytes)
                    {
                        random.nextBytes(bytes);
                    }

                    @Override
                    protected byte[] engineGenerateSeed(int numBytes)
                    {
                        return random.generateSeed(numBytes);
                    }
                };
            }
        });
    }
}
