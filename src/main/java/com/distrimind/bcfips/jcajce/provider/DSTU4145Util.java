package com.distrimind.bcfips.jcajce.provider;

import com.distrimind.bcfips.crypto.asymmetric.DSTU4145Parameters;
import com.distrimind.bcfips.jcajce.spec.DSTU4145ParameterSpec;
import com.distrimind.bcfips.jcajce.spec.ECDomainParameterSpec;

class DSTU4145Util
{
    static DSTU4145Parameters convertToECParams(DSTU4145ParameterSpec params)
    {
        return new DSTU4145Parameters(new ECDomainParameterSpec(params).getDomainParameters(), params.getDKE());
    }

    public static DSTU4145ParameterSpec convertToECSpec(DSTU4145Parameters parameters)
    {
        return new DSTU4145ParameterSpec(parameters.getDomainParameters());
    }
}
