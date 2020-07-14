package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.InvalidWrappingException;
import com.distrimind.bcfips.crypto.KeyUnwrapper;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the approved mode KeyUnwrapper implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this key unwrapper.
 */
public abstract class FipsKeyUnwrapper<T extends Parameters>
    implements KeyUnwrapper<T>
{
    // protect constructor
    FipsKeyUnwrapper()
    {

    }

    public abstract byte[] unwrap(byte[] in, int inOff, int inLen)
        throws InvalidWrappingException;
}

