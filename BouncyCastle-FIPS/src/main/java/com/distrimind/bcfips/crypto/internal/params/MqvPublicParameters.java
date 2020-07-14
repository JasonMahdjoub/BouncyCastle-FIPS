package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.internal.CipherParameters;

public class MqvPublicParameters
    implements CipherParameters
{
    private DhPublicKeyParameters staticPublicKey;
    private DhPublicKeyParameters ephemeralPublicKey;

    public MqvPublicParameters(
        DhPublicKeyParameters staticPublicKey,
        DhPublicKeyParameters ephemeralPublicKey)
    {
        this.staticPublicKey = staticPublicKey;
        this.ephemeralPublicKey = ephemeralPublicKey;

        if (!staticPublicKey.getParameters().equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalKeyException("Static and ephemeral keys have different domain parameters");
        }
    }

    public DhPublicKeyParameters getStaticPublicKey()
    {
        return staticPublicKey;
    }

    public DhPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
