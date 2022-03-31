package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.Agreement;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the FIPS approved mode Agreement implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this key agreement.
 */
public abstract class FipsAgreement<T extends Parameters>
    implements Agreement<T>
{
    // package protect construction
    FipsAgreement()
    {
    }

    public abstract T getParameters();

    public abstract byte[] calculate(AsymmetricPublicKey key);
}
