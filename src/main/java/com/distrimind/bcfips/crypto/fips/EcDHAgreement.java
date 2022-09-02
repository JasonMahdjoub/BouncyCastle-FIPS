package com.distrimind.bcfips.crypto.fips;

import java.math.BigInteger;

import com.distrimind.bcfips.crypto.asymmetric.AsymmetricECPublicKey;
import com.distrimind.bcfips.crypto.asymmetric.ECDomainParameters;
import com.distrimind.bcfips.crypto.asymmetric.NamedECDomainParameters;
import com.distrimind.bcfips.crypto.internal.BasicAgreement;
import com.distrimind.bcfips.crypto.internal.params.EcDomainParameters;
import com.distrimind.bcfips.crypto.internal.params.EcMqvPublicParameters;
import com.distrimind.bcfips.crypto.internal.params.EcNamedDomainParameters;
import com.distrimind.bcfips.crypto.internal.params.EcPublicKeyParameters;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.util.BigIntegers;

class EcDHAgreement<T extends FipsAgreementParameters>
    extends FipsAgreement<T>
{
    private final BasicAgreement dh;
    private final T parameter;

    EcDHAgreement(BasicAgreement dh, T parameter)
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

        int length = dh.getFieldSize();

        BigInteger z;
        if (dh instanceof EcMqvBasicAgreement)
        {
            AsymmetricECPublicKey ephPublicKey = ((FipsEC.MQVAgreementParameters)parameter).getOtherPartyEphemeralKey();
            z = dh.calculateAgreement(new EcMqvPublicParameters(lwECKey, new EcPublicKeyParameters(ephPublicKey.getW(), getDomainParams(ephPublicKey.getDomainParameters()))));
        }
        else
        {
            z = dh.calculateAgreement(lwECKey);
        }

        byte[] zBytes = BigIntegers.asUnsignedByteArray(length, z);

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
