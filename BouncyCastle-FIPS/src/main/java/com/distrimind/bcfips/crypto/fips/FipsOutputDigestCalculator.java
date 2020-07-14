package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.OutputDigestCalculator;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

/**
 * Base class for the approved mode OutputDigestCalculator implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this calculator.
 */
public abstract class FipsOutputDigestCalculator<T>
    implements OutputDigestCalculator<T>
{
    // package protect construction
    FipsOutputDigestCalculator()
    {
    }

    public final byte[] getDigest()
    {
        byte[] rv = new byte[getDigestSize()];

        getDigest(rv, 0);

        return rv;
    }

    public abstract T getParameters();

    public abstract int getDigestSize();

    public abstract int getDigestBlockSize();

    public abstract UpdateOutputStream getDigestStream();

    public abstract int getDigest(byte[] output, int offSet);

    public abstract void reset();

    public abstract FipsOutputDigestCalculator<T> clone()
        throws CloneNotSupportedException;
}
