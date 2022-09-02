package com.distrimind.bcfips.crypto.general;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.params.KeyParameterImpl;
import com.distrimind.bcfips.crypto.internal.params.ParametersWithIV;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.SymmetricSecretKey;
import com.distrimind.bcfips.crypto.fips.FipsAES;
import com.distrimind.bcfips.crypto.internal.BlockCipher;
import com.distrimind.bcfips.crypto.internal.EngineProvider;
import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;
import com.distrimind.bcfips.crypto.internal.Mac;
import com.distrimind.bcfips.crypto.internal.ValidatedSymmetricKey;
import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.util.encoders.Hex;

public final class Poly1305
{
    private Poly1305()
    {
    }

    /**
     * Raw Poly1305 algorithm, can be used for creating general purpose Poly1305 keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("Poly1305");

    private static final EngineProvider ENGINE_PROVIDER;
    private static final EngineProvider AES_ENGINE_PROVIDER;
    private static final EngineProvider CAMILLIA_ENGINE_PROVIDER;
    private static final EngineProvider SEED_ENGINE_PROVIDER;
    private static final EngineProvider SERPENT_ENGINE_PROVIDER;
    private static final EngineProvider TWOFISH_ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new Poly1305EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;

        AES_ENGINE_PROVIDER = new Poly1305WithCipherEngineProvider(FipsRegister.<BlockCipher>getProvider(FipsAES.ALGORITHM).createEngine(), Hex.decode("7be23689db44d57e92ebc8a8a3889cec"));
        CAMILLIA_ENGINE_PROVIDER = new Poly1305WithCipherEngineProvider(new CamelliaEngine(), Hex.decode("05dfbf3c18010cc02d1eec23798b62f7"));
        SEED_ENGINE_PROVIDER = new Poly1305WithCipherEngineProvider(new SEEDEngine(), Hex.decode("b916a6635980a54822304a84cf8e5cfd"));
        SERPENT_ENGINE_PROVIDER = new Poly1305WithCipherEngineProvider(new SerpentEngine(), Hex.decode("f7c50b5c4eed1fbb6595fa04a36b33a0"));
        TWOFISH_ENGINE_PROVIDER = new Poly1305WithCipherEngineProvider(new TwofishEngine(), Hex.decode("63c7226bf5344b102fd1906d7b20dc1c"));
    }

    public static final AuthParameters MAC = new AuthParameters(ALGORITHM);
    public static final AuthParameters MACwithAES = new AuthParameters(ALGORITHM, AES_ENGINE_PROVIDER);
    public static final AuthParameters MACwithCAMELLIA = new AuthParameters(ALGORITHM, CAMILLIA_ENGINE_PROVIDER);
    public static final AuthParameters MACwithSEED = new AuthParameters(ALGORITHM, SEED_ENGINE_PROVIDER);
    public static final AuthParameters MACwithSerpent = new AuthParameters(ALGORITHM, SERPENT_ENGINE_PROVIDER);
    public static final AuthParameters MACwithTwofish = new AuthParameters(ALGORITHM, TWOFISH_ENGINE_PROVIDER);

    public static final class AuthParameters
        extends GeneralAuthParameters<AuthParameters>
    {
        private final boolean ivRequired;
        private final EngineProvider engineProvider;

        private AuthParameters(GeneralAlgorithm algorithm, boolean ivRequired, byte[] iv, int tagLenInBits, EngineProvider engineProvider)
        {
            super(algorithm, 16, iv, tagLenInBits);
            this.ivRequired = ivRequired;
            this.engineProvider = engineProvider;
        }

        /**
         * Base constructor - the algorithm, null IV.
         * In this case the tag length defaults to the 128.
         *
         * @param algorithm algorithm mode.
         */
        AuthParameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, false, null, 128, ENGINE_PROVIDER);
        }

        AuthParameters(GeneralAlgorithm algorithm, EngineProvider engineProvider)
        {
            this(algorithm, true, null, 128, engineProvider);
        }

        protected AuthParameters create(GeneralAlgorithm algorithm, byte[] iv, int macSizeInBits)
        {
            return new AuthParameters(algorithm, this.ivRequired, iv, macSizeInBits, this.engineProvider);
        }
    }

    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private static final int keySizeInBits = 256;

        private final GeneralAlgorithm algorithm;
        private final SecureRandom random;

        public KeyGenerator(SecureRandom random)
        {
            this(ALGORITHM, random);
        }

        public KeyGenerator(GeneralParameters parameterSet, SecureRandom random)
        {
             this((GeneralAlgorithm)parameterSet.getAlgorithm(), random);
        }

        private KeyGenerator(GeneralAlgorithm algorithm, SecureRandom random)
        {
            this.algorithm = algorithm;
            this.random = random;
        }

        public SymmetricKey doGenerateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new Poly1305KeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    public static final class MACOperatorFactory
        extends GuardedMACOperatorFactory<AuthParameters>
    {
        @Override
        protected Mac createMAC(SymmetricKey key, final AuthParameters parameters)
        {
            Mac poly1305 = (Mac)parameters.engineProvider.createEngine();

            if (parameters.ivRequired)
            {
                if (parameters.iv == null)
                {
                    throw new IllegalArgumentException("Poly1305 requires a 128 bit IV when used with a block cipher");
                }
                poly1305.init(new ParametersWithIV(
                    new KeyParameterImpl(validateKey(key, parameters.getAlgorithm()).getKeyBytes()),
                    parameters.iv));
            }
            else
            {
                poly1305.init(new KeyParameterImpl(validateKey(key, parameters.getAlgorithm()).getKeyBytes()));
            }

            return poly1305;
        }

        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return Utils.bitsToBytes(parameters.macLenInBits);
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm algorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (invalidKeySize(keyLength))
        {
            throw new IllegalKeyException("Poly1305 key must be 256 bits");
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, algorithm);

        return vKey;
    }

    private static boolean invalidKeySize(int keyLength)
    {
        return keyLength != 256;
    }

    private static final class Poly1305EngineProvider
        implements EngineProvider<Mac>
    {
        static final byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
        static final byte[] output = Hex.decode("ef9e732a7f2df185a71180ae583a0f93");
        static final byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        public Mac createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new Poly1305Impl(), new VariantKatTest<Poly1305Impl>()
            {
                public void evaluate(Poly1305Impl engine)
                {
                    byte[] tmp = new byte[engine.getMacSize()];

                    engine.init(new KeyParameterImpl(key));

                    engine.update(input, 0, input.length);

                    engine.doFinal(tmp, 0);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }
                }
            });
        }
    }

    private static final class Poly1305WithCipherEngineProvider
        implements EngineProvider<Mac>
    {
        private static final byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
        private static final byte[] iv = Hex.decode("000102030405060708090a0b0c0d0e0f");
        private static final byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        private final byte[] output;
        private final BlockCipher engine;

        public Poly1305WithCipherEngineProvider(BlockCipher engine, byte[] output)
        {
            this.engine = engine;
            this.output = output;
        }

        public Mac createEngine()
        {
            Poly1305Impl impl = new Poly1305Impl(engine);

            return SelfTestExecutor.validate(ALGORITHM, impl, new VariantKatTest<Poly1305Impl>()
            {
                public void evaluate(Poly1305Impl engine)
                {
                    byte[] tmp = new byte[engine.getMacSize()];

                    engine.init(new ParametersWithIV(new KeyParameterImpl(key), iv));

                    engine.update(input, 0, input.length);

                    engine.doFinal(tmp, 0);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }
                }
            });
        }
    }
}
