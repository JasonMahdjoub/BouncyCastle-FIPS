package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.internal.params.KeyParameterImpl;

class GOST28147Parameters
    extends KeyParameterImpl
{
    private final byte[]  sBox;

    public GOST28147Parameters(
        byte[] key,
        byte[] sBox)
    {
        super(key);
        this.sBox = sBox;
    }

    public byte[] getSBox()
    {
        return sBox;
    }
}
