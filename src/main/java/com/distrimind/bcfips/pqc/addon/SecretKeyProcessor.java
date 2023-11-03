package com.distrimind.bcfips.pqc.addon;

import javax.crypto.SecretKey;

/**
 * Base interface for classes that permute secret keys based on some other value.
 */
public interface SecretKeyProcessor
{
    /**
     * Transform the passed in secret key returning the result.
     *
     * @param initialKey the key to be processed.
     * @return a new secret key.
     */
    SecretKey processKey(SecretKey initialKey);
}
