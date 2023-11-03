package com.distrimind.bcfips.pqc.addon;

import com.distrimind.bcfips.crypto.SecretWithEncapsulation;

interface EncapsulatedSecretGenerator
{
    /**
     * Generate an exchange pair based on the recipient public key.
     *
     * @return An SecretWithEncapsulation derived from the recipient public key.
     */
    SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey);
}
