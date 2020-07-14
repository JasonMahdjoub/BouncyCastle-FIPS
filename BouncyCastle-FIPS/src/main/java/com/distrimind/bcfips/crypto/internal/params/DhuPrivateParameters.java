package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.internal.CipherParameters;

public class DhuPrivateParameters
    implements CipherParameters
{
    private DhPrivateKeyParameters staticPrivateKey;
    private DhPrivateKeyParameters ephemeralPrivateKey;
    private DhPublicKeyParameters ephemeralPublicKey;

    public DhuPrivateParameters(
        DhPrivateKeyParameters staticPrivateKey,
        DhPrivateKeyParameters ephemeralPrivateKey)
    {
        this(staticPrivateKey, ephemeralPrivateKey, new DhPublicKeyParameters(
            ephemeralPrivateKey.getParameters().getG().modPow(ephemeralPrivateKey.getX(), ephemeralPrivateKey.getParameters().getP()), ephemeralPrivateKey.getParameters()));
    }

    public DhuPrivateParameters(
        DhPrivateKeyParameters staticPrivateKey,
        DhPrivateKeyParameters ephemeralPrivateKey,
        DhPublicKeyParameters ephemeralPublicKey)
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

    public DhPrivateKeyParameters getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

    public DhPrivateKeyParameters getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public DhPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
