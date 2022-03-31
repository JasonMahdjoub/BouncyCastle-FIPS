package com.distrimind.bcfips.crypto.internal;

public interface EngineProvider<T>
{
    T createEngine();
}
