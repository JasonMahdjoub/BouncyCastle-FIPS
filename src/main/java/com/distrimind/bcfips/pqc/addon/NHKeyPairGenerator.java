package com.distrimind.bcfips.pqc.addon;

import java.security.SecureRandom;


class NHKeyPairGenerator
{
    private SecureRandom random;

    public void init(SecureRandom param)
    {
        this.random = param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pubData = new byte[NewHope.SENDA_BYTES];
        short[] secData = new short[NewHope.POLY_SIZE];

        NewHope.keygen(random, pubData, secData);

        return new AsymmetricCipherKeyPair(new NHPublicKeyParameters(pubData), new NHPrivateKeyParameters(secData));
    }
}
