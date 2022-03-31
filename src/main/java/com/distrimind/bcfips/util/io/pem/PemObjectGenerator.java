/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.util.io.pem;

/**
 * Base interface for generators of PEM objects.
 */
public interface PemObjectGenerator
{
    /**
     * Generate a PEM object.
     *
     * @return the generated object.
     * @throws PemGenerationException on failure.
     */
    PemObject generate()
        throws PemGenerationException;
}
