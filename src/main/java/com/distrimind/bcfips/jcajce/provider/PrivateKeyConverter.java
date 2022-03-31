package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;

interface PrivateKeyConverter<T extends AsymmetricPrivateKey>
{
    T convertKey(Algorithm algorithm, PrivateKey key)
        throws InvalidKeyException;
}
