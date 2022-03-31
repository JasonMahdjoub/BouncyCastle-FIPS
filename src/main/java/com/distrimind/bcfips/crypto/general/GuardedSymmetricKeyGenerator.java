package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.SymmetricKeyGenerator;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedSymmetricKeyGenerator<T extends Parameters>
    implements SymmetricKeyGenerator
{
    // package protect constructor
    GuardedSymmetricKeyGenerator()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public final SymmetricKey generateKey()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to generate key for unapproved algorithm in approved only mode");
        }

        return doGenerateKey();
    }

    protected abstract SymmetricKey doGenerateKey();
}
