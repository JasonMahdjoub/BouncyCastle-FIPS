package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.OutputSigner;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.PlainInputProcessingException;

/**
 * Base class for a FIPS signature generator..
 *
 * @param <T> The parameters class for this signer.
 */
public abstract class FipsOutputSigner<T extends Parameters>
    implements OutputSigner<T>
{
    // package protect construction
    FipsOutputSigner()
    {
    }

    public abstract T getParameters();

    public abstract com.distrimind.bcfips.crypto.UpdateOutputStream getSigningStream();

    public abstract byte[] getSignature()
        throws PlainInputProcessingException;

    public abstract int getSignature(byte[] output, int off)
        throws PlainInputProcessingException;
}
