package com.distrimind.bcfips.crypto.fips;

import java.io.InputStream;

import com.distrimind.bcfips.crypto.InputAEADDecryptor;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

/**
 * Base class for the approved mode InputAEADDecryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this decryptor.
 */
public abstract class FipsInputAEADDecryptor<T extends Parameters>
    implements InputAEADDecryptor<T>
{
    // package protect construction
    FipsInputAEADDecryptor()
    {
    }

    public abstract T getParameters();

    public abstract UpdateOutputStream getAADStream();

    public abstract InputStream getDecryptingStream(InputStream in);

    public abstract byte[] getMAC();
}
