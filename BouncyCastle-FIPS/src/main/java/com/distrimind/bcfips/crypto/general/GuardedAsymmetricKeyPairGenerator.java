package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.AsymmetricKeyPairGenerator;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricKeyPair;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedAsymmetricKeyPairGenerator<T extends Parameters, P extends AsymmetricPublicKey, S extends AsymmetricPrivateKey>
    implements AsymmetricKeyPairGenerator<T, P, S>
{
    private T parameters;

    // package protect construction
    GuardedAsymmetricKeyPairGenerator(T parameters)
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }

        this.parameters = parameters;
    }

    public final T getParameters()
    {
        return parameters;
    }

    public final AsymmetricKeyPair<P, S> generateKeyPair()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to generate key for unapproved algorithm in approved only mode");
        }

        return doGenerateKeyPair();
    }

    protected abstract AsymmetricKeyPair<P, S> doGenerateKeyPair();
}
