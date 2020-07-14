package com.distrimind.bcfips.crypto.fips;

import java.math.BigInteger;

import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPair;
import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;
import com.distrimind.bcfips.crypto.internal.params.DhKeyGenerationParameters;
import com.distrimind.bcfips.crypto.internal.params.DhParameters;
import com.distrimind.bcfips.crypto.internal.params.DhPrivateKeyParameters;
import com.distrimind.bcfips.crypto.internal.params.DhPublicKeyParameters;

/**
 * a Diffie-Hellman key pair generator.
 *
 * This generates keys consistent for use in the MTI/A0 key agreement protocol
 * as described in "Handbook of Applied Cryptography", Pages 516-519.
 */
class DhKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DhKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DhKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DhKeyGeneratorHelper helper = DhKeyGeneratorHelper.INSTANCE;
        DhParameters dhp = param.getParameters();

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new DhPublicKeyParameters(y, dhp),
            new DhPrivateKeyParameters(x, dhp));
    }
}
