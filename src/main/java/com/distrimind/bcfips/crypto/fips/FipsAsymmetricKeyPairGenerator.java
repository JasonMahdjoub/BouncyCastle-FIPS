package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.asymmetric.AsymmetricKeyPair;
import com.distrimind.bcfips.crypto.AsymmetricKeyPairGenerator;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.Parameters;

/**
 * Base class for the FIPS approved mode AsymmetricKeyPairGenerator implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this generator.
 */
public abstract class FipsAsymmetricKeyPairGenerator<T extends Parameters, P extends AsymmetricPublicKey, S extends AsymmetricPrivateKey>
    implements AsymmetricKeyPairGenerator
{
    private T parameters;

    // package protect construction
    FipsAsymmetricKeyPairGenerator(T parameters)
    {
        this.parameters = parameters;
    }

    public final T getParameters()
    {
        return parameters;
    }

    public abstract AsymmetricKeyPair<P,S> generateKeyPair();
}
