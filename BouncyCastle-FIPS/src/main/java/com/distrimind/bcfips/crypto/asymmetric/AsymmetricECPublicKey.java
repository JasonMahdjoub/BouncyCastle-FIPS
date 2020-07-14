package com.distrimind.bcfips.crypto.asymmetric;

import com.distrimind.bcfips.asn1.ASN1Encodable;
import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bcfips.asn1.x9.X9ECPoint;
import com.distrimind.bcfips.asn1.x9.X9ObjectIdentifiers;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.math.ec.ECPoint;

/**
 * Class for Elliptic Curve (EC) public keys.
 */
public final class AsymmetricECPublicKey
    extends AsymmetricECKey
    implements AsymmetricPublicKey
{
    private final ECPoint q;

    public AsymmetricECPublicKey(Algorithm ecAlg, ECDomainParametersID domainParameterID, byte[] encodedPoint)
    {
        super(ecAlg, domainParameterID);

        this.q = KeyUtils.validated(getDomainParameters().getCurve(), encodedPoint);
    }

    public AsymmetricECPublicKey(Algorithm ecAlg, ECDomainParameters domainParameters, byte[] encodedPoint)
    {
        super(ecAlg, domainParameters);

        this.q = KeyUtils.validated(getDomainParameters().getCurve(), encodedPoint);
    }

    public AsymmetricECPublicKey(Algorithm ecAlg, ECDomainParametersID domainParameterID, ECPoint q)
    {
        super(ecAlg, domainParameterID);

        this.q = KeyUtils.validated(getDomainParameters().getCurve(), q);
    }

    public AsymmetricECPublicKey(Algorithm ecAlg, ECDomainParameters domainParameters, ECPoint q)
    {
        super(ecAlg, domainParameters);

        this.q = KeyUtils.validated(getDomainParameters().getCurve(), q);
    }

    public AsymmetricECPublicKey(Algorithm ecAlg, byte[] publicKeyInfoEncoding)
    {
        this(ecAlg, SubjectPublicKeyInfo.getInstance(publicKeyInfoEncoding));
    }

    public AsymmetricECPublicKey(Algorithm ecAlg, SubjectPublicKeyInfo publicKeyInfo)
    {
        super(ecAlg, publicKeyInfo.getAlgorithm());

        // really this should be getOctets() but there are keys with padbits out in the wild
        byte[] encodedPoint = publicKeyInfo.getPublicKeyData().getBytes();

        this.q = KeyUtils.validated(getDomainParameters().getCurve(), encodedPoint);
    }

    public byte[] getEncoded()
    {
        ECDomainParameters curveParams = this.getDomainParameters();
        ASN1Encodable params = KeyUtils.buildCurveParameters(curveParams);

        SubjectPublicKeyInfo info;

        ASN1OctetString p = ASN1OctetString.getInstance(new X9ECPoint(getW()).toASN1Primitive());

        info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), p.getOctets());

        return KeyUtils.getEncodedInfo(info);
    }

    public ECPoint getW()
    {
        return q;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricECPublicKey))
        {
            return false;
        }

        AsymmetricECPublicKey other = (AsymmetricECPublicKey)o;

        if (!q.equals(other.q))
        {
            return false;
        }

        return this.getDomainParameters().equals(other.getDomainParameters());
    }

    @Override
    public int hashCode()
    {
        int result = q.hashCode();
        result = 31 * result + this.getDomainParameters().hashCode();
        return result;
    }
}