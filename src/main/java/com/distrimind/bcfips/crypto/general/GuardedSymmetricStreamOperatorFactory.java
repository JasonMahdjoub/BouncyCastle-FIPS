package com.distrimind.bcfips.crypto.general;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.CipherOutputStream;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.InputDecryptor;
import com.distrimind.bcfips.crypto.OperatorUsingSecureRandom;
import com.distrimind.bcfips.crypto.OutputDecryptor;
import com.distrimind.bcfips.crypto.OutputEncryptor;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.SymmetricOperatorFactory;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;
import com.distrimind.bcfips.crypto.internal.StreamCipher;
import com.distrimind.bcfips.crypto.internal.io.CipherInputStream;
import com.distrimind.bcfips.crypto.internal.io.CipherOutputStreamImpl;

abstract class GuardedSymmetricStreamOperatorFactory<T extends Parameters>
    implements SymmetricOperatorFactory<T>
{
    // package protect constructor
    GuardedSymmetricStreamOperatorFactory()
    {
        if (!FipsStatus.isReady())
        {
            throw new FipsUnapprovedOperationError("Module has not entered the ready state.");
        }
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved mode");
        }
    }

    public final OutputEncryptor<T> createOutputEncryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved mode", parameters.getAlgorithm());
        }

        return new OutEncryptor(key, parameters, null);
    }

    public OutputDecryptor<T> createOutputDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved mode", parameters.getAlgorithm());
        }

        final StreamCipher cipher = createCipher(false, key, parameters, null);

        return new OutputDecryptor<T>()
        {
            public CipherOutputStreamImpl getDecryptingStream(OutputStream out)
            {
                return new CipherOutputStreamImpl(out, cipher);
            }

            public T getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return inputLen;
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return inputLen;
            }
        };
    }

    public final InputDecryptor<T> createInputDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved mode", parameters.getAlgorithm());
        }

        final StreamCipher cipher = createCipher(false, key, parameters, null);

        return new InputDecryptor<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public InputStream getDecryptingStream(InputStream in)
            {
                return new CipherInputStream(in, cipher);
            }
        };
    }

    protected abstract StreamCipher createCipher(boolean forEncryption, SymmetricKey key, T parameters, SecureRandom random);

    private class OutEncryptor
        implements OutputEncryptor<T>, OperatorUsingSecureRandom<OutputEncryptor<T>>
    {
        private final T parameters;
        private final SymmetricKey key;
        private final StreamCipher cipher;

        public OutEncryptor(SymmetricKey key, T parameters, SecureRandom random)
        {
            this.key = key;
            this.parameters = parameters;

            cipher = createCipher(true, key, parameters, random);
        }

        public CipherOutputStream getEncryptingStream(OutputStream out)
        {
            return new CipherOutputStreamImpl(out, cipher);
        }

        public OutputEncryptor<T> withSecureRandom(SecureRandom random)
        {
            return new OutEncryptor(key, parameters, random);
        }

        public T getParameters()
        {
            return parameters;
        }

        public int getMaxOutputSize(int inputLen)
        {
            return inputLen;
        }

        public int getUpdateOutputSize(int inputLen)
        {
            return inputLen;
        }
    }
}
