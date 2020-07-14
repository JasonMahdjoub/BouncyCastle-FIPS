package com.distrimind.bcfips.crypto.fips;

import java.io.OutputStream;

import com.distrimind.bcfips.crypto.CipherOutputStream;
import com.distrimind.bcfips.crypto.OutputEncryptor;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the approved mode OutputEncryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this encryptor.
 */
public abstract class FipsOutputEncryptor<T extends Parameters>
    implements OutputEncryptor<T>
{
     // package protect construction
    FipsOutputEncryptor()
    {
    }

    public abstract T getParameters();

    public abstract CipherOutputStream getEncryptingStream(OutputStream out);
}
