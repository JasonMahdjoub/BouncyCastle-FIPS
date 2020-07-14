package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidKeyException;
import java.security.PublicKey;

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;

interface PublicKeyConverter<T extends AsymmetricPublicKey>
{
    T convertKey(Algorithm algorithm, PublicKey key)
        throws InvalidKeyException;
}
