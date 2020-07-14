package com.distrimind.bcfips.jcajce.interfaces;

import java.security.spec.AlgorithmParameterSpec;

import com.distrimind.bcfips.jcajce.spec.GOST3410ParameterSpec;

/**
 * Main interface for a GOST keys.
 */
public interface GOST3410Key<T extends AlgorithmParameterSpec>
{
    GOST3410ParameterSpec<T> getParams();
}
