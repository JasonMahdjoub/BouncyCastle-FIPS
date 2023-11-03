package com.distrimind.bcfips.pqc.addon;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;

import com.distrimind.bcfips.crypto.SecretWithEncapsulation;
import com.distrimind.bcfips.util.Arrays;

public class SecretWithEncapsulationImpl
    implements SecretWithEncapsulation
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[] sessionKey;
    private final byte[] cipher_text;

    public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipher_text)
    {
        this.sessionKey = sessionKey;
        this.cipher_text = cipher_text;
    }

    public byte[] getSecret()
    {
        checkDestroyed();

        return Arrays.clone(sessionKey);
    }

    public byte[] getEncapsulation()
    {
        checkDestroyed();

        return Arrays.clone(cipher_text);
    }

    public void destroy()
        throws DestroyFailedException
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.fill(sessionKey, (byte)0);
            Arrays.fill(cipher_text, (byte)0);
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    void checkDestroyed()
    {
        if (isDestroyed())
        {
            throw new IllegalStateException("data has been destroyed");
        }
    }
}
