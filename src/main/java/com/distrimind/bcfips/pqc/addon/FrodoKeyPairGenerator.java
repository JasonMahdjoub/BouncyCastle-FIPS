package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;
import java.security.SecureRandom;

class FrodoKeyPairGenerator
{
    private FrodoKeyGenerationParameters frodoParams;

    private int n;
    private int D;
    private int B;

    private SecureRandom random;

    private void initialize(
        FrodoKeyGenerationParameters param)
    {
        this.frodoParams = (FrodoKeyGenerationParameters)param;
        this.random = param.getRandom();

        this.n = this.frodoParams.getParameters().getN();
        this.D = this.frodoParams.getParameters().getD();
        this.B = this.frodoParams.getParameters().getB();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        FrodoEngine engine = frodoParams.getParameters().getEngine();
        byte[] sk = new byte[engine.getPrivateKeySize()];
        byte[] pk = new byte[engine.getPublicKeySize()];
        try
        {
            engine.kem_keypair(pk, sk, random);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("kem_keypair failed!", e);
        }

        FrodoPublicKeyParameters pubKey = new FrodoPublicKeyParameters(frodoParams.getParameters(), pk);
        FrodoPrivateKeyParameters privKey = new FrodoPrivateKeyParameters(frodoParams.getParameters(), sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    public void init(FrodoKeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }

}
