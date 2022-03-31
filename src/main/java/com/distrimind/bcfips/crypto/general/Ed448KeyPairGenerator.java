package com.distrimind.bcfips.crypto.general;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPair;
import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;

class Ed448KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(random);
        Ed448PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
