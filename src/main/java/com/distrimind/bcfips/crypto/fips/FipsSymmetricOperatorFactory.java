package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.SymmetricOperatorFactory;

/**
 * Base class for the approved mode SymmetricOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsSymmetricOperatorFactory<T extends Parameters>
    implements SymmetricOperatorFactory<T>
{
    // package protect constructor
    FipsSymmetricOperatorFactory()
    {
          FipsStatus.isReady();
    }

    public abstract FipsOutputEncryptor<T> createOutputEncryptor(SymmetricKey key, T parameter);

    public abstract FipsOutputDecryptor<T> createOutputDecryptor(SymmetricKey key, T parameter);

    public abstract FipsInputDecryptor<T> createInputDecryptor(SymmetricKey key, T parameter);
}
