package com.distrimind.bcfips.crypto.fips;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.OutputSignerUsingSecureRandom;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.PlainInputProcessingException;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

/**
 * Base class for a FIPS signature generator that makes use of a SecureRandom as part of the signing process.
 *
 * @param <T> The parameters class for this signer.
 */
public abstract class FipsOutputSignerUsingSecureRandom<T extends Parameters>
    extends FipsOutputSigner<T>
    implements OutputSignerUsingSecureRandom<T>
{
    // package protect construction
    FipsOutputSignerUsingSecureRandom()
    {
    }

    public abstract T getParameters();

    public abstract UpdateOutputStream getSigningStream();

    public abstract byte[] getSignature()
        throws PlainInputProcessingException;

    public abstract FipsOutputSignerUsingSecureRandom<T> withSecureRandom(SecureRandom random);
}
