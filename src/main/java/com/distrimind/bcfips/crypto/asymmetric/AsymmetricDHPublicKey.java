package com.distrimind.bcfips.crypto.asymmetric;

import java.io.IOException;
import java.math.BigInteger;

import com.distrimind.bcfips.asn1.ASN1Integer;
import com.distrimind.bcfips.asn1.oiw.ElGamalParameter;
import com.distrimind.bcfips.asn1.oiw.OIWObjectIdentifiers;
import com.distrimind.bcfips.asn1.pkcs.DHParameter;
import com.distrimind.bcfips.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bcfips.asn1.x9.DomainParameters;
import com.distrimind.bcfips.asn1.x9.ValidationParams;
import com.distrimind.bcfips.asn1.x9.X9ObjectIdentifiers;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;

/**
 * Class for Diffie-Hellman public keys.
 */
public final class AsymmetricDHPublicKey
    extends AsymmetricDHKey
    implements AsymmetricPublicKey
{
    private BigInteger y;
    private SubjectPublicKeyInfo publicKeyInfo;

    public AsymmetricDHPublicKey(Algorithm algorithm, DHDomainParameters params, BigInteger y)
    {
        super(algorithm, params);

        this.y = KeyUtils.validated(params, y);
    }

    public AsymmetricDHPublicKey(Algorithm algorithm, byte[] enc)
    {
        this(algorithm, SubjectPublicKeyInfo.getInstance(enc));
    }

    public AsymmetricDHPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
    {
        super(algorithm, publicKeyInfo.getAlgorithm());

        this.y = KeyUtils.validated(getDomainParameters(), parsePublicKey(publicKeyInfo));
        this.publicKeyInfo = publicKeyInfo;
    }

    private static BigInteger parsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
    {
        ASN1Integer derY;

        try
        {
            derY = ASN1Integer.getInstance(publicKeyInfo.parsePublicKey());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Invalid info structure in DH public key");
        }

        if (derY == null)
        {
            throw new NullPointerException("keyData in SubjectPublicKeyInfo is empty");
        }

        return derY.getValue();
    }

    public BigInteger getY()
    {
        return y;
    }

    public byte[] getEncoded()
    {
        DHDomainParameters params = this.getDomainParameters();

        if (publicKeyInfo != null)
        {
            return KeyUtils.getEncodedInfo(publicKeyInfo);
        }

        if (params.getQ() == null)
        {
            if (getAlgorithm().getName().startsWith("ELGAMAL"))
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(params.getP(), params.getG())), new ASN1Integer(y));
            }
            return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(params.getP(), params.getG(), params.getL())), new ASN1Integer(y));
        }
        else
        {
            DHValidationParameters validationParameters = params.getValidationParameters();

            if (validationParameters != null)
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(params.getP(), params.getG(), params.getQ(), params.getJ(),
                    new ValidationParams(validationParameters.getSeed(), validationParameters.getCounter()))), new ASN1Integer(y));
            }
            else
            {
                return KeyUtils.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(params.getP(), params.getG(), params.getQ(), params.getJ(), null)), new ASN1Integer(y));
            }
        }
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricDHPublicKey))
        {
            return false;
        }

        AsymmetricDHPublicKey other = (AsymmetricDHPublicKey)o;

        return y.equals(other.y) && this.getDomainParameters().equals(other.getDomainParameters());
    }

    @Override
    public int hashCode()
    {
        int result = y.hashCode();
        result = 31 * result + this.getDomainParameters().hashCode();
        return result;
    }
}
