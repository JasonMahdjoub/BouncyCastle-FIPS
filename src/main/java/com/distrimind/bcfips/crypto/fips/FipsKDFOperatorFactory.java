package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.KDFOperatorFactory;

/**
 * Base class for the approved mode KDFOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsKDFOperatorFactory<T extends FipsParameters>
    implements KDFOperatorFactory<T>
{
    protected final boolean approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();

    // package protect constructor
    FipsKDFOperatorFactory()
    {
        FipsStatus.isReady();
    }
}
