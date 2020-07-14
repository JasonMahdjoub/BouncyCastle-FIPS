package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.fips.FipsAlgorithm;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.Mac;

class Register
{
    private Register()
    {

    }

    static Digest createDigest(Algorithm algorithm)
    {
        if (algorithm instanceof FipsAlgorithm)
        {
            return (Digest)FipsRegister.getProvider((FipsAlgorithm)algorithm).createEngine();
        }

        return SecureHash.createDigest((GeneralDigestAlgorithm)algorithm);
    }

    static Mac createHMac(Algorithm algorithm)
    {
        if (algorithm instanceof FipsAlgorithm)
        {
            return (Mac)FipsRegister.getProvider((FipsAlgorithm)algorithm).createEngine();
        }

        return SecureHash.createHMac((GeneralDigestAlgorithm)algorithm);
    }
}
