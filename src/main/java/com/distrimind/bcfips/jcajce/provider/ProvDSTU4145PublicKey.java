package com.distrimind.bcfips.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.spec.ECPoint;

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricDSTU4145PublicKey;
import com.distrimind.bcfips.jcajce.interfaces.DSTU4145PublicKey;
import com.distrimind.bcfips.jcajce.spec.DSTU4145ParameterSpec;
import com.distrimind.bcfips.jcajce.spec.DSTU4145PublicKeySpec;
import com.distrimind.bcfips.util.Strings;

class ProvDSTU4145PublicKey
    implements DSTU4145PublicKey, ProvKey<AsymmetricDSTU4145PublicKey>
{
    private static final long serialVersionUID = 7026240464295649314L;
    private transient AsymmetricDSTU4145PublicKey baseKey;

    ProvDSTU4145PublicKey(
        Algorithm algorithm,
        DSTU4145PublicKey key)
    {
        DSTU4145ParameterSpec params = key.getParams();

        this.baseKey = new AsymmetricDSTU4145PublicKey(algorithm, DSTU4145Util.convertToECParams(params), ECUtil.convertPoint(params, key.getW()));
    }


    ProvDSTU4145PublicKey(
        Algorithm algorithm,
        DSTU4145PublicKeySpec keySpec)
    {
        DSTU4145ParameterSpec params = keySpec.getParams();

        this.baseKey = new AsymmetricDSTU4145PublicKey(algorithm,  DSTU4145Util.convertToECParams(params), ECUtil.convertPoint(params, keySpec.getW()));
    }

    ProvDSTU4145PublicKey(
        AsymmetricDSTU4145PublicKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricDSTU4145PublicKey getBaseKey()
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

    public DSTU4145ParameterSpec getParams()
    {
        return DSTU4145Util.convertToECSpec(baseKey.getParameters());
    }

    public ECPoint getW()
    {
        return new ECPoint(baseKey.getW().getAffineXCoord().toBigInteger(), baseKey.getW().getAffineYCoord().toBigInteger());
    }

    public String toString()
    {
        return KeyUtil.publicKeyToString("DSTU4145", baseKey.getW().normalize(), baseKey.getParameters().getDomainParameters());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvDSTU4145PublicKey))
        {
            return false;
        }

        ProvDSTU4145PublicKey other = (ProvDSTU4145PublicKey)o;

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

        baseKey = new AsymmetricDSTU4145PublicKey(alg, enc);
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
