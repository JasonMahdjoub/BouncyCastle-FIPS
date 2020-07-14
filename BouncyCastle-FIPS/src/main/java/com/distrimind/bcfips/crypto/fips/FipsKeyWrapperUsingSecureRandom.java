package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.KeyWrapperUsingSecureRandom;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the approved mode KeyWrapper implementations which need a SecureRandom.
 *
 * @param <T> the parameters type associated with the final implementation of this key wrapper.
 */
public abstract class FipsKeyWrapperUsingSecureRandom<T extends Parameters>
    extends FipsKeyWrapper<T>
    implements KeyWrapperUsingSecureRandom<T>
{
    // protect constructor
    FipsKeyWrapperUsingSecureRandom()
    {

    }
}
