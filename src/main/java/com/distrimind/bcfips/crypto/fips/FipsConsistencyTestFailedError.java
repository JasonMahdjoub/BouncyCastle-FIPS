package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.Algorithm;

/**
 * Error thrown if a key pair consistency test fails.
 */
public class FipsConsistencyTestFailedError
    extends FipsOperationError
{
    /**
     * Base constructor.
     *
     * @param message a message describing the error.
     * @param algorithm the algorithm the failure was for.
     */
    public FipsConsistencyTestFailedError(String message, Algorithm algorithm)
    {
        super(message + ": " + algorithm.getName());
    }
}
