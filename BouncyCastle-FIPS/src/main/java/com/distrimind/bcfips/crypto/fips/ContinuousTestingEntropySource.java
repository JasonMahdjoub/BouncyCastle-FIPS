package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.EntropySource;
import com.distrimind.bcfips.util.Arrays;

class ContinuousTestingEntropySource
    implements EntropySource
{
    private final EntropySource entropySource;

    private byte[] buf;

    public ContinuousTestingEntropySource(EntropySource entropySource)
    {
        this.entropySource = entropySource;
    }

    public boolean isPredictionResistant()
    {
        return entropySource.isPredictionResistant();
    }

    public byte[] getEntropy()
    {
        synchronized (this)
        {
            byte[] nxt;

            if (buf == null)
            {
                buf = entropySource.getEntropy();
            }

            // FSM_STATE:5.1, "CONTINUOUS NDRBG TEST", "The module is performing Continuous NDRNG self-test"
            // FSM_TRANS:5.2, "CONDITIONAL TEST", "CONTINUOUS NDRNG TEST", "Invoke Continuous NDRNG test"
            nxt = entropySource.getEntropy();

            if (Arrays.areEqual(nxt, buf))
            {
                // FSM_TRANS:5.4, "CONTINUOUS NDRNG TEST", "SOFT ERROR", "Continuous NDRNG test failed"
                FipsStatus.moveToErrorStatus("Duplicate block detected in EntropySource output");
            }
            // FSM_TRANS:5.3, "CONTINUOUS NDRNG TEST", "CONDITIONAL TEST", "Continuous NDRNG test successful"

            System.arraycopy(nxt, 0, buf, 0, buf.length);

            return nxt;
        }
    }

    public int entropySize()
    {
        return entropySource.entropySize();
    }
}
