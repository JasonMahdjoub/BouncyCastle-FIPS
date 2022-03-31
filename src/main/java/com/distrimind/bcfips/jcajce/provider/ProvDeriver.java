package com.distrimind.bcfips.jcajce.provider;

import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEParameterSpec;

import com.distrimind.bcfips.crypto.PasswordBasedDeriver;

interface ProvDeriver
{
    byte[][] getSecretKeyAndIV(PBEKey pbeKey, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits, int ivvSizeInBits);

    byte[] getSecretKey(PBEKey pbeKey, PBEParameterSpec pbeSpec, PasswordBasedDeriver.KeyType keyType, int keySizeInBits);
}
