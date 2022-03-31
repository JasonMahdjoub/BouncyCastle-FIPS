package com.distrimind.bcfips.crypto.general;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPair;
import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;

class X25519KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
