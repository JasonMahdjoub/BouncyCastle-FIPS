package com.distrimind.bcfips.crypto;

import javax.security.auth.Destroyable;

/**
 * Marker interface for a private key,
 */
public interface AsymmetricPrivateKey
    extends Destroyable, AsymmetricKey
{
}
