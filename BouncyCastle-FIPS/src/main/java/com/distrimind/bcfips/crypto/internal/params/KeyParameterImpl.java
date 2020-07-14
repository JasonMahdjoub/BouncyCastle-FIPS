package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.util.Arrays;

public class KeyParameterImpl
    implements KeyParameter
{
    private byte[]  key;

    public KeyParameterImpl(
        byte[] key)
    {
        this.key = key;
    }

    public KeyParameterImpl(byte[] keyvalue, int offSet, int length)
    {
        this.key = Arrays.copyOfRange(keyvalue, offSet, offSet + length);
    }

    public byte[] getKey()
    {
        return key;
    }
}
