package com.distrimind.bcfips.jcajce.provider;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import com.distrimind.bcfips.crypto.asymmetric.ECDomainParameters;
import com.distrimind.bcfips.crypto.asymmetric.ECImplicitDomainParameters;
import com.distrimind.bcfips.jcajce.spec.ECDomainParameterSpec;
import com.distrimind.bcfips.jcajce.spec.ECImplicitDomainParameterSpec;
import com.distrimind.bcfips.math.ec.ECCurve;

class ECUtil
{
    public static ECParameterSpec convertToSpec(
        ECDomainParameters domainParameters)
    {
        if (domainParameters instanceof ECImplicitDomainParameters)
        {
            return new ECImplicitDomainParameterSpec((ECImplicitDomainParameters)domainParameters);
        }

        return new ECDomainParameterSpec(domainParameters);
    }

    public static ECDomainParameters convertFromSpec(
        ECParameterSpec ecSpec)
    {
        ECDomainParameters domainParameters;
        if (ecSpec instanceof ECDomainParameterSpec)
        {
            domainParameters = ((ECDomainParameterSpec)ecSpec).getDomainParameters();
        }
        else
        {
            domainParameters = new ECDomainParameterSpec(ecSpec).getDomainParameters();
        }

        if (ecSpec instanceof ECImplicitDomainParameterSpec)
        {
            return new ECImplicitDomainParameters(domainParameters);
        }

        return domainParameters;
    }

    public static com.distrimind.bcfips.math.ec.ECPoint convertPoint(
        ECParameterSpec ecSpec,
        ECPoint point)
    {
        return convertPoint(convertFromSpec(ecSpec).getCurve(), point);
    }

    public static com.distrimind.bcfips.math.ec.ECPoint convertPoint(
        ECCurve curve,
        ECPoint point)
    {
        return curve.validatePoint(point.getAffineX(), point.getAffineY());
    }
}
