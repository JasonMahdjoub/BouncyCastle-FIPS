package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;

class FrodoKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private FrodoEngine engine;

    private FrodoKeyParameters key;

    public FrodoKEMExtractor(FrodoKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }

    private void initCipher(FrodoParameters param)
    {
        engine = param.getEngine();
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        byte[] session_key = new byte[engine.getSessionKeySize()];
        try
        {
            engine.kem_dec(session_key, encapsulation, ((FrodoPrivateKeyParameters)key).getPrivateKey());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("kem_dec failed!", e);
        }

        return session_key;
    }

    public int getInputSize()
    {
        return engine.getCipherTextSize();
    }
}
