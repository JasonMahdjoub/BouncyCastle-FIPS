package com.distrimind.bcfips.jcajce.spec;

import java.security.spec.ECParameterSpec;

import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.asymmetric.ECDomainParameters;
import com.distrimind.bcfips.crypto.asymmetric.ECImplicitDomainParameters;

/**
 * Extension of ECParameterSpec which marks a parameter set as being the ImplicitlyCA parameters for this JVM.
 */
public final class ECImplicitDomainParameterSpec
    extends ECParameterSpec
{
    /**
     * Default constructor - create the spec using the value of the property CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA
     */
    public ECImplicitDomainParameterSpec()
    {
        this(ECUtil.convertToSpec(CryptoServicesRegistrar.<ECDomainParameters>getProperty(CryptoServicesRegistrar.Property.EC_IMPLICITLY_CA)));
    }

    /**
     * Constructor wrapping ECImplicitDomainParameters.
     *
     * @param implicitDomainParameters the EC ImplicitlyCA parameters to wrap.
     */
    public ECImplicitDomainParameterSpec(ECImplicitDomainParameters implicitDomainParameters)
    {
        this(ECUtil.convertToSpec(implicitDomainParameters));
    }

    private ECImplicitDomainParameterSpec(ECParameterSpec spec)
    {
        super(spec.getCurve(), spec.getGenerator(), spec.getOrder(), spec.getCofactor());
    }
}
