package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.crypto.internal.CipherParameters;

/**
 * Created by dgh on 16/06/15.
 */
public interface KeyParameter
    extends CipherParameters
{
    byte[] getKey();
}
