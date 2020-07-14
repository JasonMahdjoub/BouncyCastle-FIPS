package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.KeyUnwrapperUsingSecureRandom;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the approved mode KeyUnwrapper implementations which need a SecureRandom.
 *
 * @param <T> the parameters type associated with the final implementation of this key unwrapper.
 */
public abstract class FipsKeyUnwrapperUsingSecureRandom<T extends Parameters>
    extends FipsKeyUnwrapper<T>
    implements KeyUnwrapperUsingSecureRandom<T>
{
    // protect constructor
    FipsKeyUnwrapperUsingSecureRandom()
    {

    }
}
