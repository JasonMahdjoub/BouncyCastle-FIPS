package com.distrimind.bcfips.crypto.general;

import java.util.HashMap;
import java.util.Map;

import com.distrimind.bcfips.crypto.internal.EngineProvider;
import com.distrimind.bcfips.crypto.fips.FipsAlgorithm;
import com.distrimind.bcfips.crypto.fips.FipsEngineProvider;

/**
 * Local register that provides access to engines for FIPS algorithms for use with general/non-FIPS-approved modes of use.
 */
public final class FipsRegister
{
    FipsRegister()
    {

    }

    private static final Map<FipsAlgorithm, EngineProvider> providerMap = new HashMap<FipsAlgorithm, EngineProvider>();

    public static void registerEngineProvider(FipsAlgorithm algorithm, FipsEngineProvider provider)
    {
        if (algorithm == null || provider == null)
        {
            throw new IllegalArgumentException("Arguments cannot be null");
        }

        providerMap.put(algorithm, provider);
    }

    static <T> EngineProvider<T> getProvider(FipsAlgorithm algorithm)
    {
        return providerMap.get(algorithm);
    }
}
