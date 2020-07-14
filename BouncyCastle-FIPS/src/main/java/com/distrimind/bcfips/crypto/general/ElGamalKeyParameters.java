package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.internal.params.AsymmetricKeyParameter;

class ElGamalKeyParameters
    extends AsymmetricKeyParameter
{
    private final ElGamalParameters    params;

    protected ElGamalKeyParameters(
        boolean              isPrivate,
        ElGamalParameters    params)
    {
        super(isPrivate);

        this.params = params;
    }   

    public ElGamalParameters getParameters()
    {
        return params;
    }
}
