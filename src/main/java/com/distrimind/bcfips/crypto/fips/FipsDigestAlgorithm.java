package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.DigestAlgorithm;

/**
 * Marker class for a FIPS approved digest algorithm
 */
public class FipsDigestAlgorithm
    extends FipsAlgorithm
    implements DigestAlgorithm
{
    FipsDigestAlgorithm(String name, Enum basicVariation)
    {
        super(name, basicVariation);
    }
}
