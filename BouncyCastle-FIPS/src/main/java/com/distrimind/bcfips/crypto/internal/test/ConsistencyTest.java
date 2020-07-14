package com.distrimind.bcfips.crypto.internal.test;

public interface ConsistencyTest<T>
{
    boolean hasTestPassed(T parameters) throws Exception;
}
