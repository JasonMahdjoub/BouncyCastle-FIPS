package com.distrimind.bcfips.util.test;

import com.distrimind.bcfips.util.encoders.Hex;

/**
 * A fixed secure random designed to return data for someone needing random bytes.
 */
public class TestRandomData
    extends FixedSecureRandom
{
    /**
     * Constructor from a Hex encoding of the data.
     *
     * @param encoding a Hex encoding of the data to be returned.
     */
    public TestRandomData(String encoding)
    {
        super(new FixedSecureRandom.Data(Hex.decode(encoding)));
    }

    /**
     * Constructor from an array of bytes.
     *
     * @param encoding a byte array representing the data to be returned.
     */
    public TestRandomData(byte[] encoding)
    {
        super(new FixedSecureRandom.Data(encoding));
    }
}
