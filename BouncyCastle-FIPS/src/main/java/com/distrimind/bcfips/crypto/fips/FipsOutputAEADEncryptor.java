package com.distrimind.bcfips.crypto.fips;

import java.io.OutputStream;

import com.distrimind.bcfips.crypto.CipherOutputStream;
import com.distrimind.bcfips.crypto.OutputAEADEncryptor;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

/**
 * Base class for the approved mode OutputAEADEncryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this key encryptor.
 */
public abstract class FipsOutputAEADEncryptor<T extends FipsParameters>
    extends FipsOutputEncryptor<T>
    implements OutputAEADEncryptor<T>
{
    // package protect construction
    FipsOutputAEADEncryptor()
    {
    }

    public abstract UpdateOutputStream getAADStream();

    public abstract CipherOutputStream getEncryptingStream(OutputStream out);

    public abstract byte[] getMAC();
}
