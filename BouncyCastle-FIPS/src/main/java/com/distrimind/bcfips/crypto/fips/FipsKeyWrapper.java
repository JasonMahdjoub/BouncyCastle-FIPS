package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.KeyWrapper;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the approved mode KeyWrapper implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this key wrapper.
 */
public abstract class FipsKeyWrapper<T extends Parameters>
    implements KeyWrapper<T>
{
    // protect constructor
    FipsKeyWrapper()
    {

    }
}
