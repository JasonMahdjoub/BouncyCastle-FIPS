package com.distrimind.bcfips.pqc.addon;

import com.distrimind.bcfips.util.Arrays;

class NHPublicKeyParameters
{
    final byte[] pubData;

    public NHPublicKeyParameters(byte[] pubData)
    {
        this.pubData = Arrays.clone(pubData);
    }

    /**
     * Return the public key data.
     *
     * @return the public key values.
     */
    public byte[] getPubData()
    {
        return Arrays.clone(pubData);
    }
}
