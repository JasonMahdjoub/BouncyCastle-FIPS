package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;
import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.SecretWithEncapsulation;

class CMCEKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public CMCEKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        CMCEPublicKeyParameters key = (CMCEPublicKeyParameters)recipientKey;
        CMCEEngine engine = key.getParameters().getEngine();

        return generateEncapsulated(recipientKey, engine.getDefaultSessionKeySize());
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey, int sessionKeySizeInBits)
    {
        CMCEPublicKeyParameters key = (CMCEPublicKeyParameters)recipientKey;
        CMCEEngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[sessionKeySizeInBits / 8];     // document as 32 - l/8  - Section 2.5.2
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
