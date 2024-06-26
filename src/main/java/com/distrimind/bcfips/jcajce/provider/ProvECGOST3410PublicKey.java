package com.distrimind.bcfips.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.spec.ECPoint;

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricECGOST3410PublicKey;
import com.distrimind.bcfips.jcajce.interfaces.ECGOST3410PublicKey;
import com.distrimind.bcfips.jcajce.spec.ECDomainParameterSpec;
import com.distrimind.bcfips.jcajce.spec.ECGOST3410PublicKeySpec;
import com.distrimind.bcfips.jcajce.spec.GOST3410ParameterSpec;
import com.distrimind.bcfips.util.Strings;

class ProvECGOST3410PublicKey
    implements ECGOST3410PublicKey, ProvKey<AsymmetricECGOST3410PublicKey>
{
    private static final long serialVersionUID = 7026240464295649314L;

    private transient AsymmetricECGOST3410PublicKey baseKey;

    ProvECGOST3410PublicKey(
        Algorithm algorithm,
        ECGOST3410PublicKey key)
    {
        GOST3410ParameterSpec<ECDomainParameterSpec> params = key.getParams();

        this.baseKey = new AsymmetricECGOST3410PublicKey(algorithm, GOST3410Util.convertToECParams(params), ECUtil.convertPoint(params.getDomainParametersSpec(), key.getW()));
    }


    ProvECGOST3410PublicKey(
        Algorithm algorithm,
        ECGOST3410PublicKeySpec keySpec)
    {
        GOST3410ParameterSpec<ECDomainParameterSpec> params = keySpec.getParams();

        this.baseKey = new AsymmetricECGOST3410PublicKey(algorithm,  GOST3410Util.convertToECParams(params), ECUtil.convertPoint(params.getDomainParametersSpec(), keySpec.getW()));
    }

    ProvECGOST3410PublicKey(
        AsymmetricECGOST3410PublicKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricECGOST3410PublicKey getBaseKey()
    {
        return baseKey;
    }

    public String getAlgorithm()
    {
        return baseKey.getAlgorithm().getName();
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public GOST3410ParameterSpec<ECDomainParameterSpec> getParams()
    {
        return GOST3410Util.convertToECSpec(baseKey.getParameters());
    }

    public ECPoint getW()
    {
        return new ECPoint(baseKey.getW().getAffineXCoord().toBigInteger(), baseKey.getW().getAffineYCoord().toBigInteger());
    }

    public String toString()
    {
        return KeyUtil.publicKeyToString("ECGOST3410", baseKey.getW(), baseKey.getParameters().getDomainParameters());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvECGOST3410PublicKey))
        {
            return false;
        }

        ProvECGOST3410PublicKey other = (ProvECGOST3410PublicKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricECGOST3410PublicKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }
}
