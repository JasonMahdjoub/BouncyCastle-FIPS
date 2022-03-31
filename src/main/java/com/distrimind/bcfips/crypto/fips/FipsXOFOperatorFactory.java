package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.XOFOperatorFactory;

/**
 * Base class for the approved mode XOFOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsXOFOperatorFactory<T extends FipsParameters>
    implements XOFOperatorFactory<T>
{
    // package protect constructor
    FipsXOFOperatorFactory()
    {
        FipsStatus.isReady();
    }

    public abstract FipsOutputXOFCalculator<T> createOutputXOFCalculator(T parameter);
}
