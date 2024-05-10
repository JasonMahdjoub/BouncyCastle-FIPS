package com.distrimind.bcfips.crypto.fips;

import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedAction;

import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.internal.ValidatedSymmetricKey;

class PrivilegedUtils
{
    static ValidatedSymmetricKey getValidatedKey(SymmetricKey key)
    {
        return new ValidatedSymmetricKey(key.getAlgorithm(), PrivilegedUtils.getKeyBytes(key));
    }

    static byte[] getKeyBytes(final SymmetricKey sKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<byte[]>()
        {
            public byte[] run()
            {
                return sKey.getKeyBytes();
            }
        });
    }

    static void checkPermission(final Permission permission)
    {
        final SecurityManager securityManager = System.getSecurityManager();

        if (securityManager != null)
        {
            AccessController.doPrivileged(new PrivilegedAction<Object>()
            {
                public Object run()
                {
                    securityManager.checkPermission(permission);

                    return null;
                }
            });
        }
    }
}
