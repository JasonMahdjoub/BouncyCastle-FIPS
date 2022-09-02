/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.crypto.fips;

import java.math.BigInteger;

import com.distrimind.bcfips.crypto.internal.BasicAgreement;
import com.distrimind.bcfips.crypto.internal.CipherParameters;
import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.internal.params.EcDomainParameters;
import com.distrimind.bcfips.crypto.internal.params.EcMqvPrivateParameters;
import com.distrimind.bcfips.crypto.internal.params.EcMqvPublicParameters;
import com.distrimind.bcfips.crypto.internal.params.EcPrivateKeyParameters;
import com.distrimind.bcfips.crypto.internal.params.EcPublicKeyParameters;
import com.distrimind.bcfips.math.ec.ECAlgorithms;
import com.distrimind.bcfips.math.ec.ECConstants;
import com.distrimind.bcfips.math.ec.ECCurve;
import com.distrimind.bcfips.math.ec.ECPoint;

class EcMqvBasicAgreement
    implements BasicAgreement
{
    EcMqvPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (EcMqvPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public BigInteger calculateAgreement(CipherParameters pubKey)
    {
        EcMqvPublicParameters pubParams = (EcMqvPublicParameters)pubKey;

        EcPrivateKeyParameters staticPrivateKey = privParams.getStaticPrivateKey();
        EcDomainParameters parameters = staticPrivateKey.getParameters();

        if (!parameters.equals(pubParams.getStaticPublicKey().getParameters()))
        {
            throw new IllegalKeyException("ECMQV public key components have wrong domain parameters");
        }

        ECPoint agreement = calculateMqvAgreement(parameters, staticPrivateKey,
            privParams.getEphemeralPrivateKey(), privParams.getEphemeralPublicKey(),
            pubParams.getStaticPublicKey(), pubParams.getEphemeralPublicKey()).normalize();

        if (agreement.isInfinity())
        {
            throw new IllegalStateException("Infinity is not a valid agreement value for MQV");
        }

        return agreement.getAffineXCoord().toBigInteger();
    }

    // The ECMQV Primitive as described in SEC-1, 3.4
    private ECPoint calculateMqvAgreement(
        EcDomainParameters      parameters,
        EcPrivateKeyParameters  d1U,
        EcPrivateKeyParameters  d2U,
        EcPublicKeyParameters Q2U,
        EcPublicKeyParameters   Q1V,
        EcPublicKeyParameters   Q2V)
    {
        BigInteger n = parameters.getN();
        int e = (n.bitLength() + 1) / 2;
        BigInteger powE = ECConstants.ONE.shiftLeft(e);

        ECCurve curve = parameters.getCurve();

        // The Q2U public key is optional - but will be calculated for us if it wasn't present
        ECPoint q2u = ECAlgorithms.cleanPoint(curve, Q2U.getQ());
        ECPoint q1v = ECAlgorithms.cleanPoint(curve, Q1V.getQ());
        ECPoint q2v = ECAlgorithms.cleanPoint(curve, Q2V.getQ());

        BigInteger x = q2u.getAffineXCoord().toBigInteger();
        BigInteger xBar = x.mod(powE);
        BigInteger Q2UBar = xBar.setBit(e);
        BigInteger s = d1U.getD().multiply(Q2UBar).add(d2U.getD()).mod(n);

        BigInteger xPrime = q2v.getAffineXCoord().toBigInteger();
        BigInteger xPrimeBar = xPrime.mod(powE);
        BigInteger Q2VBar = xPrimeBar.setBit(e);

        BigInteger hs = parameters.getH().multiply(s).mod(n);

        return ECAlgorithms.sumOfTwoMultiplies(
            q1v, Q2VBar.multiply(hs).mod(n), q2v, hs);
    }
}
