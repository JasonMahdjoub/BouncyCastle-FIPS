package com.distrimind.bcfips.pqc.addon;

import com.distrimind.bcfips.util.Arrays;

/**
 * Pair for a value exchange algorithm where the responding party has no private key, such as NewHope.
 */
class ExchangePair
{
    private final Object publicKey;
    private final byte[] shared;

    /**
     * Base constructor.
     *
     * @param publicKey The responding party's public key.
     * @param shared the calculated shared value.
     */
    public ExchangePair(Object publicKey, byte[] shared)
    {
        this.publicKey = publicKey;
        this.shared = Arrays.clone(shared);
    }

    /**
     * Return the responding party's public key.
     *
     * @return the public key calculated for the exchange.
     */
    public Object getPublicKey()
    {
        return publicKey;
    }

    /**
     * Return the shared value calculated with public key.
     *
     * @return the shared value.
     */
    public byte[] getSharedValue()
    {
        return Arrays.clone(shared);
    }
}
