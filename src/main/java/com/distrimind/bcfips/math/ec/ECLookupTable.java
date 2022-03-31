package com.distrimind.bcfips.math.ec;

public interface ECLookupTable
{
    int getSize();
    ECPoint lookup(int index);
}
