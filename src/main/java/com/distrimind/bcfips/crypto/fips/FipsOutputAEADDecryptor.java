package com.distrimind.bcfips.crypto.fips;

import java.io.OutputStream;

import com.distrimind.bcfips.crypto.CipherOutputStream;
import com.distrimind.bcfips.crypto.OutputAEADDecryptor;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

/**
 * Base class for the approved mode OutputAEADDecryptor implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this decryptor.
 */
public abstract class FipsOutputAEADDecryptor<T extends FipsParameters>
    extends FipsOutputDecryptor<T>
    implements OutputAEADDecryptor<T>
{
    // package protect construction
    FipsOutputAEADDecryptor()
    {
    }

    public abstract UpdateOutputStream getAADStream();

    public abstract CipherOutputStream getDecryptingStream(OutputStream out);

    public abstract byte[] getMAC();
}
