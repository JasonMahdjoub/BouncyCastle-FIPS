package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.DigestOperatorFactory;

/**
 * Base class for classes that produce digest calculators implementing the various FIPS secure hash algorithms.
 *
 * @param <T> The parameters class for this signer.
 */
public abstract class FipsDigestOperatorFactory<T extends FipsParameters>
    implements DigestOperatorFactory<T>
{
    // package protect constructor
    FipsDigestOperatorFactory()
    {
         FipsStatus.isReady();
    }

    public abstract FipsOutputDigestCalculator<T> createOutputDigestCalculator(final T parameter);
}
