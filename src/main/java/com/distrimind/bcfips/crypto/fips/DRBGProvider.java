package com.distrimind.bcfips.crypto.fips;

import com.distrimind.bcfips.crypto.EntropySource;

interface DRBGProvider
{
    DRBG get(EntropySource entropySource);
}
