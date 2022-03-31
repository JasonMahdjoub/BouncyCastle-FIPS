package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.internal.CipherParameters;

public class EcMqvPrivateParameters
    implements CipherParameters
{
    private EcPrivateKeyParameters staticPrivateKey;
    private EcPrivateKeyParameters ephemeralPrivateKey;
    private EcPublicKeyParameters ephemeralPublicKey;

    public EcMqvPrivateParameters(
        EcPrivateKeyParameters staticPrivateKey,
        EcPrivateKeyParameters ephemeralPrivateKey)
    {
        this(staticPrivateKey, ephemeralPrivateKey,
            new EcPublicKeyParameters(ephemeralPrivateKey.getParameters().getG().multiply(ephemeralPrivateKey.getD()), ephemeralPrivateKey.getParameters()));
    }

    public EcMqvPrivateParameters(
        EcPrivateKeyParameters staticPrivateKey,
        EcPrivateKeyParameters ephemeralPrivateKey,
        EcPublicKeyParameters ephemeralPublicKey)
    {
        this.staticPrivateKey = staticPrivateKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.ephemeralPublicKey = ephemeralPublicKey;

        if (!staticPrivateKey.getParameters().equals(ephemeralPrivateKey.getParameters())
            || !staticPrivateKey.getParameters().equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalKeyException("Static and ephemeral keys have different domain parameters");
        }
    }

    public EcPrivateKeyParameters getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

    public EcPrivateKeyParameters getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public EcPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
