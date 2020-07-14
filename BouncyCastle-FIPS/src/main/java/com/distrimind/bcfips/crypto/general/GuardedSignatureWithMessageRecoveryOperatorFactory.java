package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.OutputSignerWithMessageRecovery;
import com.distrimind.bcfips.crypto.OutputVerifierWithMessageRecovery;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SignatureWithMessageRecoveryOperatorFactory;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedSignatureWithMessageRecoveryOperatorFactory<T extends Parameters>
    implements SignatureWithMessageRecoveryOperatorFactory<T>
{
    // package protect constructor
    GuardedSignatureWithMessageRecoveryOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public final OutputSignerWithMessageRecovery<T> createSigner(AsymmetricPrivateKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateSigner(key, parameters);
    }

    public final OutputVerifierWithMessageRecovery<T> createVerifier(AsymmetricPublicKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateVerifier(key, parameters);
    }

    protected abstract OutputSignerWithMessageRecovery<T> doCreateSigner(AsymmetricPrivateKey key, T parameter);

    protected abstract OutputVerifierWithMessageRecovery<T> doCreateVerifier(AsymmetricPublicKey key, T parameter);
}
