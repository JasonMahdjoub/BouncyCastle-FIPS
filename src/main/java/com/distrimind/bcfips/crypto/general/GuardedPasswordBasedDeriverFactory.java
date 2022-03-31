package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.PasswordBasedDeriverFactory;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedPasswordBasedDeriverFactory<T extends Parameters>
    implements PasswordBasedDeriverFactory<T>
{
    GuardedPasswordBasedDeriverFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }
}
