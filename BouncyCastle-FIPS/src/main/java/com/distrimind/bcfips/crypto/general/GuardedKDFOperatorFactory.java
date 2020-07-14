package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.KDFOperatorFactory;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedKDFOperatorFactory<T extends Parameters>
    implements KDFOperatorFactory<T>
{
    // package protect constructor
    GuardedKDFOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }
}
