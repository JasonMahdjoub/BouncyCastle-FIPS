package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.crypto.internal.DerivationParameters;
import com.distrimind.bcfips.util.Arrays;

public final class KDFDoublePipelineIterationParameters
    implements DerivationParameters
{
    public static final int BEFORE_ITER = KDFFeedbackParameters.BEFORE_ITER;
    public static final int AFTER_ITER = KDFFeedbackParameters.AFTER_ITER;
    public static final int AFTER_FIXED = KDFFeedbackParameters.AFTER_FIXED;

    // could be any valid value, using 32, don't know why
    private static final int UNUSED_R = 32;

    private final byte[] ki;
    private final boolean useCounter;
    private final int r;
    private final byte[] fixedInputData;
    private final int counterLocation;

    private KDFDoublePipelineIterationParameters(int counterLocation, byte[] ki, byte[] fixedInputData, int r, boolean useCounter)
    {
        if (ki == null)
        {
            throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
        }

        this.counterLocation = counterLocation;
        this.ki = Arrays.clone(ki);

        if (fixedInputData == null)
        {
            this.fixedInputData = new byte[0];
        }
        else
        {
            this.fixedInputData = Arrays.clone(fixedInputData);
        }

        if (r != 8 && r != 16 && r != 24 && r != 32)
        {
            throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
        }
        this.r = r;

        this.useCounter = useCounter;
    }

    public static KDFDoublePipelineIterationParameters createWithCounter(
        int counterLocation, byte[] ki, byte[] fixedInputData, int r)
    {
        return new KDFDoublePipelineIterationParameters(counterLocation, ki, fixedInputData, r, true);
    }

    public static KDFDoublePipelineIterationParameters createWithoutCounter(
        byte[] ki, byte[] fixedInputData)
    {
        return new KDFDoublePipelineIterationParameters(BEFORE_ITER, ki, fixedInputData, UNUSED_R, false);
    }

    public int getCounterLocation()
    {
        return counterLocation;
    }

    public byte[] getKI()
    {
        return ki;
    }

    public boolean useCounter()
    {
        return useCounter;
    }

    public int getR()
    {
        return r;
    }

    public byte[] getFixedInputData()
    {
        return Arrays.clone(fixedInputData);
    }
}
