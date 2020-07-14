package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.OutputSigner;
import com.distrimind.bcfips.crypto.OutputVerifier;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SignatureOperatorFactory;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedSignatureOperatorFactory<T extends Parameters>
    implements SignatureOperatorFactory<T>
{
    // package protect constructor
    GuardedSignatureOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public final OutputSigner<T> createSigner(AsymmetricPrivateKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateSigner(key, parameters);
    }

    public final OutputVerifier<T> createVerifier(AsymmetricPublicKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateVerifier(key, parameters);
    }

    protected abstract OutputSigner<T> doCreateSigner(AsymmetricPrivateKey key, T parameter);

    protected abstract OutputVerifier<T> doCreateVerifier(AsymmetricPublicKey key, T parameter);
}
