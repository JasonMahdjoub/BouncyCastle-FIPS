package com.distrimind.bcfips.jcajce.provider;

import com.distrimind.bcfips.crypto.Key;

interface ProvKey<T extends Key>
{
    T getBaseKey();
}
