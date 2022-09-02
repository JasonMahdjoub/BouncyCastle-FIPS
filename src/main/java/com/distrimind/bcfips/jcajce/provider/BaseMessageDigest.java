package com.distrimind.bcfips.jcajce.provider;

import java.security.MessageDigest;

import com.distrimind.bcfips.crypto.OutputDigestCalculator;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.UpdateOutputStream;
import com.distrimind.bcfips.crypto.fips.FipsDigestOperatorFactory;
import com.distrimind.bcfips.crypto.fips.FipsSHS;

final class BaseMessageDigest
    extends MessageDigest
    implements Cloneable
{
    private static FipsDigestOperatorFactory<FipsSHS.Parameters> fipsFactory = new FipsSHS.OperatorFactory<FipsSHS.Parameters>();

    private final OutputDigestCalculator  digestCalculator;
    private final UpdateOutputStream digestStream;

    protected BaseMessageDigest(
        FipsSHS.Parameters algorithm)
    {
        this(fipsFactory.createOutputDigestCalculator(algorithm));
    }

    BaseMessageDigest(OutputDigestCalculator digestCalculator)
    {
        super(((Parameters)digestCalculator.getParameters()).getAlgorithm().getName());

        this.digestCalculator = digestCalculator;
        this.digestStream = digestCalculator.getDigestStream();
    }


    protected void engineReset()
    {
        digestCalculator.reset();
    }

    protected void engineUpdate(
        byte    input) 
    {
        digestStream.update(input);
    }

    protected void engineUpdate(
        byte[]  input,
        int     offset,
        int     len) 
    {
        digestStream.update(input, offset, len);
    }

    protected byte[] engineDigest()
    {
        byte[]  digestBytes = digestCalculator.getDigest();

        engineReset();

        return digestBytes;
    }

    protected int engineGetDigestLength()
    {
        return digestCalculator.getDigestSize();
    }

    public Object clone()
        throws CloneNotSupportedException
    {
        return new BaseMessageDigest(digestCalculator.clone());
    }
}
