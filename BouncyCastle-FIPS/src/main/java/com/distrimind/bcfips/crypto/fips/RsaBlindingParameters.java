/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.internal.CipherParameters;
import com.distrimind.bcfips.crypto.internal.params.RsaKeyParameters;
import com.distrimind.bcfips.crypto.internal.params.RsaPrivateCrtKeyParameters;

import java.math.BigInteger;

class RsaBlindingParameters
    implements CipherParameters
{
    private RsaKeyParameters publicKey;
    private BigInteger       blindingFactor;

    public RsaBlindingParameters(
        RsaKeyParameters publicKey,
        BigInteger       blindingFactor)
    {
        if (publicKey instanceof RsaPrivateCrtKeyParameters)
        {
            throw new IllegalArgumentException("RSA parameters should be for a public key");
        }
        
        this.publicKey = publicKey;
        this.blindingFactor = blindingFactor;
    }

    public RsaKeyParameters getPublicKey()
    {
        return publicKey;
    }

    public BigInteger getBlindingFactor()
    {
        return blindingFactor;
    }
}
