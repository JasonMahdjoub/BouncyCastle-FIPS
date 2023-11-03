package com.distrimind.bcfips.pqc.addon;

import com.distrimind.bcfips.util.Arrays;

class NHPrivateKeyParameters
{
    final short[] secData;

    public NHPrivateKeyParameters(short[] secData)
    {
        this.secData = Arrays.clone(secData);
    }

    public short[] getSecData()
    {
        return Arrays.clone(secData);
    }
}
