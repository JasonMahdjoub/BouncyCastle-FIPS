package com.distrimind.bcfips.pqc.addon;

interface EncapsulatedSecretExtractor
{
    /**
     * Generate an exchange pair based on the recipient public key.
     *
     * @param encapsulation the encapsulated secret.
     */
    byte[] extractSecret(byte[] encapsulation);
}
