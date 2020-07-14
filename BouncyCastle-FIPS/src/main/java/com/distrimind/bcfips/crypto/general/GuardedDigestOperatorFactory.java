package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.DigestOperatorFactory;
import com.distrimind.bcfips.crypto.OutputDigestCalculator;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedDigestOperatorFactory<T extends Parameters>
    implements DigestOperatorFactory<T>
{
    // package protect constructor
    GuardedDigestOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public abstract OutputDigestCalculator<T> createOutputDigestCalculator(final T parameter);
}
