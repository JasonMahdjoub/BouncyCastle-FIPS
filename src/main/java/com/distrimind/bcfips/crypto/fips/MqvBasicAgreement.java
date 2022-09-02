package com.distrimind.bcfips.crypto.fips;

import java.math.BigInteger;

import com.distrimind.bcfips.crypto.internal.BasicAgreement;
import com.distrimind.bcfips.crypto.internal.CipherParameters;
import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.internal.params.DhParameters;
import com.distrimind.bcfips.crypto.internal.params.DhPrivateKeyParameters;
import com.distrimind.bcfips.crypto.internal.params.DhPublicKeyParameters;
import com.distrimind.bcfips.crypto.internal.params.MqvPrivateParameters;
import com.distrimind.bcfips.crypto.internal.params.MqvPublicParameters;

class MqvBasicAgreement
    implements BasicAgreement
{
    MqvPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (MqvPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    public BigInteger calculateAgreement(CipherParameters pubKey)
    {
        MqvPublicParameters pubParams = (MqvPublicParameters)pubKey;

        DhPrivateKeyParameters staticPrivateKey = privParams.getStaticPrivateKey();

        if (!privParams.getStaticPrivateKey().getParameters().equals(pubParams.getStaticPublicKey().getParameters()))
        {
            throw new IllegalKeyException("MQV public key components have wrong domain parameters");
        }

        if (privParams.getStaticPrivateKey().getParameters().getQ() == null)
        {
            throw new IllegalKeyException("MQV key domain parameters do not have Q set");
        }

        BigInteger agreement = calculateMqvAgreement(staticPrivateKey.getParameters(), staticPrivateKey,
            pubParams.getStaticPublicKey(), privParams.getEphemeralPrivateKey(), privParams.getEphemeralPublicKey(),
            pubParams.getEphemeralPublicKey());

        if (agreement.equals(BigInteger.ONE))
        {
            throw new IllegalStateException("1 is not a valid agreement value for MQV");
        }

        return agreement;
    }

    private BigInteger calculateMqvAgreement(
        DhParameters parameters,
        DhPrivateKeyParameters xA,
        DhPublicKeyParameters yB,
        DhPrivateKeyParameters rA,
        DhPublicKeyParameters tA,
        DhPublicKeyParameters tB)
    {
        BigInteger q = parameters.getQ();

        int w = (q.bitLength() + 1) / 2;
        BigInteger twoW = BigInteger.valueOf(2).pow(w);

        BigInteger TA =  tA.getY().mod(twoW).add(twoW);
        BigInteger SA =  rA.getX().add(TA.multiply(xA.getX())).mod(q);
        BigInteger TB =  tB.getY().mod(twoW).add(twoW);
        BigInteger Z =   tB.getY().multiply(yB.getY().modPow(TB, parameters.getP())).modPow(SA, parameters.getP());

        return Z;
    }
}
