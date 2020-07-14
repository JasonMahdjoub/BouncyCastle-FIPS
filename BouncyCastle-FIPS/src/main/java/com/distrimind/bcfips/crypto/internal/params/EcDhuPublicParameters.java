package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.internal.CipherParameters;

public class EcDhuPublicParameters
    implements CipherParameters
{
    private EcPublicKeyParameters staticPublicKey;
    private EcPublicKeyParameters ephemeralPublicKey;

    public EcDhuPublicParameters(
        EcPublicKeyParameters staticPublicKey,
        EcPublicKeyParameters ephemeralPublicKey)
    {
        this.staticPublicKey = staticPublicKey;
        this.ephemeralPublicKey = ephemeralPublicKey;

        if (!staticPublicKey.getParameters().equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalKeyException("Static and ephemeral keys have different domain parameters");
        }
    }

    public EcPublicKeyParameters getStaticPublicKey()
    {
        return staticPublicKey;
    }

    public EcPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
