package com.distrimind.bcfips.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.MACOperatorFactory;
import com.distrimind.bcfips.crypto.OutputMACCalculator;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

class BaseMac
    extends MacSpi
{
    private final Algorithm algorithm;
    private final MACOperatorFactory factory;
    private final MacParametersCreator parametersCreator;
    private final int keySizeInBits;

    private OutputMACCalculator macCalculator;
    private UpdateOutputStream macStream;

    protected BaseMac(
        Algorithm algorithm, MACOperatorFactory factory, MacParametersCreator parametersCreator)
    {
        this(algorithm, factory, parametersCreator, 0);
    }

    protected BaseMac(
        Parameters parameters, MACOperatorFactory factory, MacParametersCreator parametersCreator)
    {
        this(parameters.getAlgorithm(), factory, parametersCreator, 0);
    }

    protected BaseMac(
        Parameters parameters, MACOperatorFactory factory, MacParametersCreator parametersCreator, int keySizeInBits)
    {
        this(parameters.getAlgorithm(), factory, parametersCreator, keySizeInBits);
    }

    protected BaseMac(
        Algorithm algorithm, MACOperatorFactory factory, MacParametersCreator parametersCreator, int keySizeInBits)
    {
        this.algorithm = algorithm;
        this.factory = factory;
        this.parametersCreator = parametersCreator;
        this.keySizeInBits = keySizeInBits;
    }

    protected void engineInit(
        Key                     key,
        AlgorithmParameterSpec  params)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        SymmetricKey symmetricKey = Utils.convertKey(algorithm, key);

        if (keySizeInBits != 0 && Utils.keyNotLength(symmetricKey, keySizeInBits))  // restricted key size
        {
            throw new InvalidKeyException("MAC requires key of size " + keySizeInBits + " bits");
        }

        try
        {
            macCalculator = factory.createOutputMACCalculator(symmetricKey, parametersCreator.createParameters(false, params, null));
            macStream = macCalculator.getMACStream();
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e.getCause());
        }
    }

    protected int engineGetMacLength()
    {
        return (parametersCreator.getBaseParameters().getMACSizeInBits() + 7) / 8;
    }

    protected void engineReset()
    {
        if (macCalculator != null)
        {
            macCalculator.reset();
        }
    }

    protected void engineUpdate(
        byte    input)
    {
        macStream.update(input);
    }

    protected void engineUpdate(
        byte[]  input,
        int     offset,
        int     len)
    {
        macStream.update(input, offset, len);
    }

    protected byte[] engineDoFinal()
    {
        return macCalculator.getMAC();
    }
}
