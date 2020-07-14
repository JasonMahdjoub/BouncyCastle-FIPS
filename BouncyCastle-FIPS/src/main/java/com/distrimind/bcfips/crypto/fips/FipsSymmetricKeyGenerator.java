package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.SymmetricKeyGenerator;
import com.distrimind.bcfips.crypto.SymmetricSecretKey;

/**
 * Base class for the FIPS approved mode SymmetricKeyGenerator implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this generator.
 */
public abstract class FipsSymmetricKeyGenerator<T extends SymmetricSecretKey>
    implements SymmetricKeyGenerator<T>
{
    // package protect constructor
    FipsSymmetricKeyGenerator()
    {
       FipsStatus.isReady();
    }
}
