package com.distrimind.bcfips.crypto.general;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;
import com.distrimind.bcfips.crypto.fips.FipsSecureRandom;

/**
 * The base class for symmetric, or secret, cipher key generators.
 */
class CipherKeyGenerator
{
    protected SecureRandom     random;
    protected int              strength;

    /**
     * initialise the key generator.
     *
     * @param param the parameters to be used for key generation
     */
    public void init(
        KeyGenerationParameters param)
    {
        this.random = param.getRandom();
        this.strength = (param.getStrength() + 7) / 8;
    }

    /**
     * generate a secret key.
     *
     * @return a byte array containing the key value.
     */
    public byte[] generateKey()
    {
        byte[]  key = new byte[strength];

        if (random instanceof FipsSecureRandom)
        {
            FipsSecureRandom fipsRandom = (FipsSecureRandom)random;

            fipsRandom.reseed();
            fipsRandom.nextBytes(key);
        }
        else
        {
            random.nextBytes(key);
        }

        return key;
    }
}
