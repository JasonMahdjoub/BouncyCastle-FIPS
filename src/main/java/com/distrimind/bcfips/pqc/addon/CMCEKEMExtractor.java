package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;

class CMCEKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private CMCEEngine engine;

    private CMCEKeyParameters key;

    public CMCEKEMExtractor(CMCEPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(key.getParameters());
    }
    
    private void initCipher(CMCEParameters param)
    {
        engine = param.getEngine();
        CMCEPrivateKeyParameters privateParams = (CMCEPrivateKeyParameters)key;
        if(privateParams.getPrivateKey().length < engine.getPrivateKeySize())
        {
            try
            {
                key = new CMCEPrivateKeyParameters(privateParams.getParameters(), engine.decompress_private_key(privateParams.getPrivateKey()));
            }
            catch (IOException e)
            {
                throw new IllegalStateException("private key failed!", e);
            }
        }
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        return extractSecret(encapsulation, engine.getDefaultSessionKeySize());
    }

    public byte[] extractSecret(byte[] encapsulation, int sessionKeySizeInBits)
    {
        byte[] session_key = new byte[sessionKeySizeInBits / 8];
        try
        {
            engine.kem_dec(session_key, encapsulation, ((CMCEPrivateKeyParameters)key).getPrivateKey());
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
