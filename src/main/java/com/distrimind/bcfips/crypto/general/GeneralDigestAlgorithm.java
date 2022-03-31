package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.DigestAlgorithm;

/**
 * Marker class for a digest algorithm
 */
public class GeneralDigestAlgorithm
    extends GeneralAlgorithm
    implements DigestAlgorithm
{
    GeneralDigestAlgorithm(String name, Enum basicVariation)
    {
        super(name, basicVariation);
    }
}
