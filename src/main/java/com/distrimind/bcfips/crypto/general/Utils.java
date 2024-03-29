package com.distrimind.bcfips.crypto.general;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.ValidatedSymmetricKey;
import com.distrimind.bcfips.crypto.internal.params.KeyParameter;
import com.distrimind.bcfips.crypto.internal.params.KeyParameterImpl;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

class Utils
{
    static final SecureRandom testRandom = new SecureRandom();

    static void approveModeCheck(Algorithm algorithm)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to use unapproved algorithm in approved only mode", algorithm);
        }
    }

    static KeyParameter getKeyParameter(ValidatedSymmetricKey sKey)
    {
        return new KeyParameterImpl(sKey.getKeyBytes());
    }

    static void checkKeyAlgorithm(ValidatedSymmetricKey key, Algorithm generalAlgorithm, Algorithm paramAlgorithm)
    {
        Algorithm keyAlgorithm = key.getAlgorithm();

        if (!keyAlgorithm.equals(generalAlgorithm))
        {
            if (!keyAlgorithm.equals(paramAlgorithm))
            {
                throw new IllegalKeyException("Key not for appropriate algorithm");
            }
        }
    }

    static int bitsToBytes(int bits)
    {
        return (bits + 7) / 8;
    }

    static int getDefaultMacSize(Algorithm algorithm, int blockSize)
    {
        if (algorithm.getName().endsWith("GMAC") || algorithm.getName().endsWith("/CMAC")
            || algorithm.getName().endsWith("GCM") || algorithm.getName().endsWith("OCB")
            || algorithm.getName().endsWith("ISO979ALG3"))
        {
            return blockSize;
        }

        return blockSize / 2;
    }
}
