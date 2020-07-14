/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.crypto.internal;

/**
 * base interface for general purpose Digest based byte derivation functions.
 */
public interface DigestDerivationFunction
    extends DerivationFunction
{
    /**
     * return the message digest used as the basis for the function
     */
    public Digest getDigest();
}
