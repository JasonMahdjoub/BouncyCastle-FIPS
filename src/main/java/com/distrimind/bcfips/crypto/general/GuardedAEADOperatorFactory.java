package com.distrimind.bcfips.crypto.general;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.distrimind.bcfips.crypto.AEADOperatorFactory;
import com.distrimind.bcfips.crypto.CipherOutputStream;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.InputAEADDecryptor;
import com.distrimind.bcfips.crypto.OutputAEADDecryptor;
import com.distrimind.bcfips.crypto.OutputAEADEncryptor;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.UpdateOutputStream;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;
import com.distrimind.bcfips.crypto.internal.io.CipherInputStream;
import com.distrimind.bcfips.crypto.internal.io.CipherOutputStreamImpl;
import com.distrimind.bcfips.crypto.internal.modes.AEADBlockCipher;

abstract class GuardedAEADOperatorFactory<T extends Parameters>
    implements AEADOperatorFactory<T>
{
    // package protect construction
    GuardedAEADOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode.");
        }
    }

    public OutputAEADEncryptor<T> createOutputAEADEncryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return new OutEncryptor(key, parameters);
    }

    public InputAEADDecryptor<T> createInputAEADDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        final AEADBlockCipher  cipher = createAEADCipher(false, key, parameters);

        return new InputAEADDecryptor<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public UpdateOutputStream getAADStream()
            {
                return new AADStream(cipher);
            }

            public InputStream getDecryptingStream(InputStream in)
            {
                return new CipherInputStream(in, cipher);
            }

            public byte[] getMAC()
            {
                return cipher.getMac();
            }
        };
    }

    public OutputAEADDecryptor<T> createOutputAEADDecryptor(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        final AEADBlockCipher cipher = createAEADCipher(false, key, parameters);

        return new OutputAEADDecryptor<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public int getMaxOutputSize(int inputLen)
            {
                return cipher.getOutputSize(inputLen);
            }

            public int getUpdateOutputSize(int inputLen)
            {
                return cipher.getUpdateOutputSize(inputLen);
            }

            public UpdateOutputStream getAADStream()
            {
                return new AADStream(cipher);
            }

            public com.distrimind.bcfips.crypto.CipherOutputStream getDecryptingStream(final OutputStream out)
            {
                return new CipherOutputStreamImpl(out, cipher);
            }

            public byte[] getMAC()
            {
                return cipher.getMac();
            }
        };
    }

    abstract protected AEADBlockCipher createAEADCipher(boolean forEncryption, SymmetricKey key, T parameters);

    private class OutEncryptor
        implements OutputAEADEncryptor<T>
    {
        private final T parameters;
        private final AEADBlockCipher cipher;

        OutEncryptor(SymmetricKey key, T parameters)
        {
            this.parameters = parameters;
            this.cipher = createAEADCipher(true, key, parameters);
        }

        public T getParameters()
        {
            return parameters;
        }

        public int getMaxOutputSize(int inputLen)
        {
            return cipher.getOutputSize(inputLen);
        }

        public int getUpdateOutputSize(int inputLen)
        {
            return cipher.getUpdateOutputSize(inputLen);
        }

        public UpdateOutputStream getAADStream()
        {
            return new AADStream(cipher);
        }

        public CipherOutputStream getEncryptingStream(final OutputStream out)
        {
            return new CipherOutputStreamImpl(out, cipher);
        }

        public byte[] getMAC()
        {
            return cipher.getMac();
        }
    }

    private class AADStream
        extends UpdateOutputStream
    {
        private AEADBlockCipher cipher;

        AADStream(AEADBlockCipher cipher)
        {
            this.cipher = cipher;
        }

        @Override
        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            cipher.processAADBytes(buf, off, len);
        }

        @Override
        public void write(int b)
            throws IOException
        {
            cipher.processAADByte((byte)b);
        }
    }
}
