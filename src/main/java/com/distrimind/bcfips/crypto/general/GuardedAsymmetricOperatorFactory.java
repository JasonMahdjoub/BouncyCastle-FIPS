package com.distrimind.bcfips.crypto.general;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.AsymmetricBlockCipher;
import com.distrimind.bcfips.crypto.internal.encodings.OAEPEncoding;
import com.distrimind.bcfips.crypto.internal.encodings.PKCS1Encoding;
import com.distrimind.bcfips.crypto.AsymmetricKey;
import com.distrimind.bcfips.crypto.AsymmetricOperatorFactory;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.PlainInputProcessingException;
import com.distrimind.bcfips.crypto.SingleBlockEncryptorUsingSecureRandom;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedAsymmetricOperatorFactory<T extends Parameters>
    implements AsymmetricOperatorFactory<T>
{
    // package protect construction
    GuardedAsymmetricOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public SingleBlockEncryptorUsingSecureRandom<T> createBlockEncryptor(final AsymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return new BlockEncryptor(key, parameters, null);
    }

    protected abstract AsymmetricBlockCipher createCipher(boolean forEncryption, AsymmetricKey key, T parameters, SecureRandom random);

    private class BlockEncryptor
        implements SingleBlockEncryptorUsingSecureRandom<T>
    {
        private final AsymmetricKey key;
        private final T parameters;
        private final SecureRandom random;

        private AsymmetricBlockCipher engine;

        BlockEncryptor(AsymmetricKey key, T parameters, SecureRandom random)
        {
            this.key = key;
            this.parameters = parameters;
            this.random = random;
        }

        private AsymmetricBlockCipher getEngine()
        {
            if (engine == null)
            {
                engine = createCipher(true, key, parameters, random);
            }

            return engine;
        }

        public byte[] encryptBlock(byte[] bytes, int offSet, int length)
            throws PlainInputProcessingException
        {
            try
            {
                Utils.approveModeCheck(parameters.getAlgorithm());

                return getEngine().processBlock(bytes, offSet, length);
            }
            catch (Exception e)
            {
                throw new PlainInputProcessingException("Unable to encrypt block: " + e.getMessage(), e);
            }
        }

        public T getParameters()
        {
            return parameters;
        }

        public int getInputSize()
        {
            Utils.approveModeCheck(parameters.getAlgorithm());

            AsymmetricBlockCipher engine = getEngine();

            // we allow one extra byte for raw engines
            if (isRawEngine(engine))
            {
                return engine.getInputBlockSize() + 1;
            }
            else
            {
                return engine.getInputBlockSize();
            }
        }

        public int getOutputSize()
        {
            Utils.approveModeCheck(parameters.getAlgorithm());

            return getEngine().getOutputBlockSize();
        }

        public SingleBlockEncryptorUsingSecureRandom<T> withSecureRandom(SecureRandom random)
        {
            Utils.approveModeCheck(parameters.getAlgorithm());

            return new BlockEncryptor(key, parameters, random);
        }
    }

    protected static boolean isRawEngine(AsymmetricBlockCipher engine)
    {
        return !(engine instanceof PKCS1Encoding) && !(engine instanceof OAEPEncoding);
    }
}
