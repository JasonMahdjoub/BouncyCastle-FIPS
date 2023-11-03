package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;
import java.security.SecureRandom;


import com.distrimind.bcfips.crypto.SecretWithEncapsulation;

class FrodoKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public FrodoKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        FrodoPublicKeyParameters key = (FrodoPublicKeyParameters)recipientKey;
        FrodoEngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[engine.getSessionKeySize()];
        try
        {
            engine.kem_enc(cipher_text, sessionKey, key.getPublicKey(), sr);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("kem_enc failed!", e);
        }
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
    }
}
