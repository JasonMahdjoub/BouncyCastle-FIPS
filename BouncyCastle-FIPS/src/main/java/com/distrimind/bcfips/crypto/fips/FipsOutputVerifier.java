package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.InvalidSignatureException;
import com.distrimind.bcfips.crypto.OutputVerifier;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

/**
 * Base class for a FIPS signature verifier.
 *
 * @param <T> The parameters class for this verifier.
 */
public abstract class FipsOutputVerifier<T extends Parameters>
    implements OutputVerifier<T>
{
    // package protect construction
    FipsOutputVerifier()
    {
    }

    public abstract T getParameters();

    public abstract UpdateOutputStream getVerifyingStream();

    public abstract boolean isVerified(byte[] signature)
        throws InvalidSignatureException;
}
