package com.distrimind.bcfips.jcajce.provider;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.SymmetricKeyGenerator;

interface KeyGeneratorCreator
{
    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random);
}
