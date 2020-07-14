package com.distrimind.bcfips.crypto.internal.test;

public interface BasicKatTest<T>
{
    boolean hasTestPassed(T engine) throws Exception;
}
