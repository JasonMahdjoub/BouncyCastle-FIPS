package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.asymmetric.AsymmetricECPublicKey;
import com.distrimind.bcfips.crypto.asymmetric.ECDomainParameters;
import com.distrimind.bcfips.crypto.asymmetric.NamedECDomainParameters;
import com.distrimind.bcfips.crypto.internal.params.EcDhuPublicParameters;
import com.distrimind.bcfips.crypto.internal.params.EcDomainParameters;
import com.distrimind.bcfips.crypto.internal.params.EcNamedDomainParameters;
import com.distrimind.bcfips.crypto.internal.params.EcPublicKeyParameters;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;

class EcDHUAgreement<T extends FipsAgreementParameters>
    extends FipsAgreement<T>
{
    private final EcDhcuBasicAgreement dh;
    private final T parameter;

    EcDHUAgreement(EcDhcuBasicAgreement dh, T parameter)
    {
        this.dh = dh;
        this.parameter = parameter;
    }

    @Override
    public T getParameters()
    {
        return parameter;
    }

    @Override
    public byte[] calculate(AsymmetricPublicKey key)
    {
        AsymmetricECPublicKey ecKey = (AsymmetricECPublicKey)key;
        EcPublicKeyParameters lwECKey = new EcPublicKeyParameters(ecKey.getW(), getDomainParams(ecKey.getDomainParameters()));

        AsymmetricECPublicKey ephPublicKey = ((FipsEC.DHUAgreementParameters)parameter).getOtherPartyEphemeralKey();
        byte[] zBytes = dh.calculateAgreement(new EcDhuPublicParameters(lwECKey, new EcPublicKeyParameters(ephPublicKey.getW(), getDomainParams(ephPublicKey.getDomainParameters()))));

        return FipsKDF.processZBytes(zBytes, parameter);
    }

    private static EcDomainParameters getDomainParams(ECDomainParameters curveParams)
    {
        if (curveParams instanceof NamedECDomainParameters)
        {
            return new EcNamedDomainParameters((NamedECDomainParameters)curveParams);
        }
        return new EcDomainParameters(curveParams);
    }
}
