package com.distrimind.bcfips.util.test;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.EntropySource;
import com.distrimind.bcfips.crypto.EntropySourceProvider;

/**
 * A class for returning "quick entropy" for testing purposes. It uses a SecureRandom but does not use SecureRandom.generateSeed().
 */
public class TestRandomEntropySourceProvider
    implements EntropySourceProvider
{
    private final SecureRandom _sr;
    private final boolean      _predictionResistant;

    /**
     * Create a test entropy source provider.
     *
     * @param isPredictionResistant boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is).
     */
    public TestRandomEntropySourceProvider(boolean isPredictionResistant)
    {
        _sr = new SecureRandom();
        _predictionResistant = isPredictionResistant;
    }

    /**
     * Return an entropy source that will create bitsRequired bits of entropy on
     * each invocation of getEntropy().
     *
     * @param bitsRequired size (in bits) of entropy to be created by the provided source.
     * @return an EntropySource that generates bitsRequired bits of entropy on each call to its getEntropy() method.
     */
    public EntropySource get(final int bitsRequired)
    {
        return new EntropySource()
        {
            public boolean isPredictionResistant()
            {
                return _predictionResistant;
            }

            public byte[] getEntropy()
            {
                byte[] rv = new byte[(bitsRequired + 7) / 8];
                _sr.nextBytes(rv);
                return rv;
            }

            public int entropySize()
            {
                return bitsRequired;
            }
        };
    }
}