package com.distrimind.bcfips.jcajce.provider;

import java.security.NoSuchAlgorithmException;

interface EngineCreator
{
    Object createInstance(Object constructorParameter)
        throws NoSuchAlgorithmException;
}
