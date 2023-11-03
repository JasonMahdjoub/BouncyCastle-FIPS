package com.distrimind.bcfips.pqc.addon;

import com.distrimind.bcfips.util.Arrays;

public class CMCEPublicKeyParameters
    extends CMCEKeyParameters
{
    private final byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public CMCEPublicKeyParameters(CMCEParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
