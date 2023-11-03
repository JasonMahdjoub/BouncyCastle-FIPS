package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;
import java.security.SecureRandom;

class CMCEKeyPairGenerator
{

    private CMCEKeyGenerationParameters cmceParams;

    private int m;

    private int n;

    private int t;

    private SecureRandom random;

    private void initialize(
        CMCEKeyGenerationParameters param)
    {
        this.cmceParams = (CMCEKeyGenerationParameters) param;
        this.random = param.getRandom();

        this.m = this.cmceParams.getParameters().getM();
        this.n = this.cmceParams.getParameters().getN();
        this.t = this.cmceParams.getParameters().getT();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        CMCEEngine engine = cmceParams.getParameters().getEngine();
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

        CMCEPublicKeyParameters pubKey = new CMCEPublicKeyParameters(cmceParams.getParameters(), pk);
        CMCEPrivateKeyParameters privKey = new CMCEPrivateKeyParameters(cmceParams.getParameters(), sk);
        return new AsymmetricCipherKeyPair(pubKey, privKey);

    }

    public void init(CMCEKeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
}
