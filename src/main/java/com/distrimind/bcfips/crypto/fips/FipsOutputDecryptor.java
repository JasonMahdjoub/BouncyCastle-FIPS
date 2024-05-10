package com.distrimind.bcfips.crypto.fips;

import java.io.OutputStream;

import com.distrimind.bcfips.crypto.OutputDecryptor;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the approved mode OutputDecryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this decryptor.
 */
public abstract class FipsOutputDecryptor<T extends Parameters>
    implements OutputDecryptor<T>
{
     // package protect construction
    FipsOutputDecryptor()
    {
    }

    public abstract T getParameters();

    public abstract com.distrimind.bcfips.crypto.CipherOutputStream getDecryptingStream(OutputStream out);
}
