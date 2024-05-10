package com.distrimind.bcfips.crypto.fips;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import com.distrimind.bcfips.crypto.AuthenticationParameters;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.SymmetricKey;
import com.distrimind.bcfips.crypto.SymmetricSecretKey;
import com.distrimind.bcfips.crypto.UpdateOutputStream;
import com.distrimind.bcfips.crypto.general.FipsRegister;
import com.distrimind.bcfips.crypto.internal.CipherKeyGenerator;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.ExtendedDigest;
import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;
import com.distrimind.bcfips.crypto.internal.Mac;
import com.distrimind.bcfips.crypto.internal.ValidatedSymmetricKey;
import com.distrimind.bcfips.crypto.internal.Xof;
import com.distrimind.bcfips.crypto.internal.io.DigestOutputStream;
import com.distrimind.bcfips.crypto.internal.io.XofOutputStream;
import com.distrimind.bcfips.crypto.internal.macs.HMac;
import com.distrimind.bcfips.crypto.internal.macs.TruncatingMac;
import com.distrimind.bcfips.crypto.internal.params.KeyParameter;
import com.distrimind.bcfips.crypto.internal.params.KeyParameterImpl;
import com.distrimind.bcfips.crypto.internal.test.BasicKatTest;
import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.util.Strings;
import com.distrimind.bcfips.util.encoders.Hex;

/**
 * Source class for implementations of FIPS approved secure hash algorithms.
 */
public final class FipsSHS
{
    private static final int MIN_APPROVED_KEY_SIZE = 112;
    private static final Map<FipsAlgorithm, Integer> defaultMacSize = new HashMap<FipsAlgorithm, Integer>();

    enum Variations
    {
        SHA1,
        SHA1_HMAC,
        SHA224,
        SHA224_HMAC,
        SHA256,
        SHA256_HMAC,
        SHA384,
        SHA384_HMAC,
        SHA512,
        SHA512_HMAC,
        SHA512_224,
        SHA512_224_HMAC,
        SHA512_256,
        SHA512_256_HMAC,
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        // order is important here...
        SHA3_224_HMAC,
        SHA3_256_HMAC,
        SHA3_384_HMAC,
        SHA3_512_HMAC
    }

    public static final class Algorithm
    {
        private Algorithm()
        {

        }

        public static final FipsDigestAlgorithm SHA1 = new FipsDigestAlgorithm("SHA-1", Variations.SHA1);
        public static final FipsDigestAlgorithm SHA1_HMAC = new FipsDigestAlgorithm("SHA-1/HMAC", Variations.SHA1_HMAC);
        public static final FipsDigestAlgorithm SHA224 = new FipsDigestAlgorithm("SHA-224", Variations.SHA224);
        public static final FipsDigestAlgorithm SHA224_HMAC = new FipsDigestAlgorithm("SHA-224/HMAC", Variations.SHA224_HMAC);
        public static final FipsDigestAlgorithm SHA256 = new FipsDigestAlgorithm("SHA-256", Variations.SHA256);
        public static final FipsDigestAlgorithm SHA256_HMAC = new FipsDigestAlgorithm("SHA-256/HMAC", Variations.SHA256_HMAC);
        public static final FipsDigestAlgorithm SHA384 = new FipsDigestAlgorithm("SHA-384", Variations.SHA384);
        public static final FipsDigestAlgorithm SHA384_HMAC = new FipsDigestAlgorithm("SHA-384/HMAC", Variations.SHA384_HMAC);
        public static final FipsDigestAlgorithm SHA512 = new FipsDigestAlgorithm("SHA-512", Variations.SHA512);
        public static final FipsDigestAlgorithm SHA512_HMAC = new FipsDigestAlgorithm("SHA-512/HMAC", Variations.SHA512_HMAC);
        public static final FipsDigestAlgorithm SHA512_224 = new FipsDigestAlgorithm("SHA-512(224)", Variations.SHA512_224);
        public static final FipsDigestAlgorithm SHA512_224_HMAC = new FipsDigestAlgorithm("SHA-512(224)/HMAC", Variations.SHA512_224_HMAC);
        public static final FipsDigestAlgorithm SHA512_256 = new FipsDigestAlgorithm("SHA-512(256)", Variations.SHA512_256);
        public static final FipsDigestAlgorithm SHA512_256_HMAC = new FipsDigestAlgorithm("SHA-512(256)/HMAC", Variations.SHA512_256_HMAC);
        public static final FipsDigestAlgorithm SHA3_224 = new FipsDigestAlgorithm("SHA3-224", Variations.SHA3_224);
        public static final FipsDigestAlgorithm SHA3_224_HMAC = new FipsDigestAlgorithm("SHA3-224/HMAC", Variations.SHA3_224_HMAC);
        public static final FipsDigestAlgorithm SHA3_256 = new FipsDigestAlgorithm("SHA3-256", Variations.SHA3_256);
        public static final FipsDigestAlgorithm SHA3_256_HMAC = new FipsDigestAlgorithm("SHA3-256/HMAC", Variations.SHA3_256_HMAC);
        public static final FipsDigestAlgorithm SHA3_384 = new FipsDigestAlgorithm("SHA3-384", Variations.SHA3_384);
        public static final FipsDigestAlgorithm SHA3_384_HMAC = new FipsDigestAlgorithm("SHA3-384/HMAC", Variations.SHA3_384_HMAC);
        public static final FipsDigestAlgorithm SHA3_512 = new FipsDigestAlgorithm("SHA3-512", Variations.SHA3_512);
        public static final FipsDigestAlgorithm SHA3_512_HMAC = new FipsDigestAlgorithm("SHA3-512/HMAC", Variations.SHA3_512_HMAC);

        public static final FipsAlgorithm SHAKE128 = new FipsAlgorithm("SHAKE128");
        public static final FipsAlgorithm SHAKE256 = new FipsAlgorithm("SHAKE256");

        public static final FipsAlgorithm cSHAKE128 = new FipsAlgorithm("cSHAKE128");
        public static final FipsAlgorithm cSHAKE256 = new FipsAlgorithm("cSHAKE256");
    }

    private static Map<FipsAlgorithm, FipsEngineProvider<ExtendedDigest>> digests = new HashMap<FipsAlgorithm, FipsEngineProvider<ExtendedDigest>>();
    private static Map<FipsAlgorithm, FipsEngineProvider<Mac>> hMacs = new HashMap<FipsAlgorithm, FipsEngineProvider<Mac>>();

    static
    {
        defaultMacSize.put(Algorithm.SHA1_HMAC, 160);
        defaultMacSize.put(Algorithm.SHA224_HMAC, 224);
        defaultMacSize.put(Algorithm.SHA256_HMAC, 256);
        defaultMacSize.put(Algorithm.SHA384_HMAC, 384);
        defaultMacSize.put(Algorithm.SHA512_HMAC, 512);
        defaultMacSize.put(Algorithm.SHA512_224_HMAC, 224);
        defaultMacSize.put(Algorithm.SHA512_256_HMAC, 256);
        defaultMacSize.put(Algorithm.SHA3_224_HMAC, 224);
        defaultMacSize.put(Algorithm.SHA3_256_HMAC, 256);
        defaultMacSize.put(Algorithm.SHA3_384_HMAC, 384);
        defaultMacSize.put(Algorithm.SHA3_512_HMAC, 512);

        final ShaKatTest sha1kat = new ShaKatTest(Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d"));
        digests.put(Algorithm.SHA1, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA1, sha1kat);
            }
        });

        final ShaKatTest sha224kat = new ShaKatTest(Hex.decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
        digests.put(Algorithm.SHA224, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA224, sha224kat);
            }
        });

        final ShaKatTest sha256kat = new ShaKatTest(Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        digests.put(Algorithm.SHA256, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA256, sha256kat);
            }
        });

        final ShaKatTest sha384kat = new ShaKatTest(Hex.decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
        digests.put(Algorithm.SHA384, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA384, sha384kat);
            }
        });

        final ShaKatTest sha512kat = new ShaKatTest(Hex.decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
        digests.put(Algorithm.SHA512, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA512, sha512kat);
            }
        });

        final ShaKatTest sha512_224kat = new ShaKatTest(Hex.decode("4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA"));
        digests.put(Algorithm.SHA512_224, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA512_224, sha512_224kat);
            }
        });

        final ShaKatTest sha512_256kat = new ShaKatTest(Hex.decode("53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23"));
        digests.put(Algorithm.SHA512_256, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA512_256, sha512_256kat);
            }
        });

        final ShaKatTest sha3_224kat = new ShaKatTest(Hex.decode("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"));
        digests.put(Algorithm.SHA3_224, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA3_224, sha3_224kat);
            }
        });

        final ShaKatTest sha3_256kat = new ShaKatTest(Hex.decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
        digests.put(Algorithm.SHA3_256, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA3_256, sha3_256kat);
            }
        });

        final ShaKatTest sha3_384kat = new ShaKatTest(Hex.decode("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"));
        digests.put(Algorithm.SHA3_384, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA3_384, sha3_384kat);
            }
        });

        final ShaKatTest sha3_512kat = new ShaKatTest(Hex.decode("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
        digests.put(Algorithm.SHA3_512, new FipsEngineProvider<ExtendedDigest>()
        {
            public ExtendedDigest createEngine()
            {
                return makeValidatedDigest(Algorithm.SHA3_512, sha3_512kat);
            }
        });

        final HMacKatTest sha1HmacKat = new HMacKatTest(Hex.decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
        hMacs.put(Algorithm.SHA1_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA1_HMAC, sha1HmacKat);
            }
        });

        final HMacKatTest sha224HmacKat = new HMacKatTest(Hex.decode("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"));
        hMacs.put(Algorithm.SHA224_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA224_HMAC, sha224HmacKat);
            }
        });

        final HMacKatTest sha256HmacKat = new HMacKatTest(Hex.decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        hMacs.put(Algorithm.SHA256_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA256_HMAC, sha256HmacKat);
            }
        });

        final HMacKatTest sha384HmacKat = new HMacKatTest(Hex.decode("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"));
        hMacs.put(Algorithm.SHA384_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA384_HMAC, sha384HmacKat);
            }
        });

        final HMacKatTest sha512HmacKat = new HMacKatTest(Hex.decode("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
        hMacs.put(Algorithm.SHA512_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA512_HMAC, sha512HmacKat);
            }
        });

        final HMacKatTest sha512_224HmacKat = new HMacKatTest(Hex.decode("4a530b31a79ebcce36916546317c45f247d83241dfb818fd37254bde"));
        hMacs.put(Algorithm.SHA512_224_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA512_224_HMAC, sha512_224HmacKat);
            }
        });

        final HMacKatTest sha512_256HmacKat = new HMacKatTest(Hex.decode("6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456"));
        hMacs.put(Algorithm.SHA512_256_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA512_256_HMAC, sha512_256HmacKat);
            }
        });

        final HMacKatTest sha3_224HmacKat = new HMacKatTest(Hex.decode("7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66"));
        hMacs.put(Algorithm.SHA3_224_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA3_224_HMAC, sha3_224HmacKat);
            }
        });

        final HMacKatTest sha3_256HmacKat = new HMacKatTest(Hex.decode("c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"));
        hMacs.put(Algorithm.SHA3_256_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA3_256_HMAC, sha3_256HmacKat);
            }
        });

        final HMacKatTest sha3_384HmacKat = new HMacKatTest(Hex.decode("f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a"));
        hMacs.put(Algorithm.SHA3_384_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA3_384_HMAC, sha3_384HmacKat);
            }
        });

        final HMacKatTest sha3_512HmacKat = new HMacKatTest(Hex.decode("5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024"));
        hMacs.put(Algorithm.SHA3_512_HMAC, new FipsEngineProvider<Mac>()
        {
            public Mac createEngine()
            {
                return makeValidatedHMac(Algorithm.SHA3_512_HMAC, sha3_512HmacKat);
            }
        });

        // FSM_STATE:3.SHS.0,"SECURE HASH GENERATE VERIFY KAT", "The module is performing Secure Hash generate and verify KAT self-tests"
        // FSM_TRANS:3.SHS.0, "POWER ON SELF-TEST",	"SECURE HASH GENERATE VERIFY KAT",	"Invoke Secure Hash Generate/Verify KAT self-test"
        digests.get(Algorithm.SHA1).createEngine();        // As per IG 9.4 for SHA-3 see XOF test
        digests.get(Algorithm.SHA256).createEngine();
        digests.get(Algorithm.SHA512).createEngine();
        // FSM_TRANS:3.SHS.1, "SECURE HASH GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"Secure Hash Generate/Verify KAT self-test successful completion"

        // FSM_STATE:3.SHS.1,"HMAC GENERATE VERIFY KAT", "The module is performing HMAC generate and verify KAT self-tests"
        // FSM_TRANS:3.SHS.2,"POWER ON SELF-TEST", "HMAC GENERATE VERIFY KAT", "Invoke HMAC Generate/Verify KAT self-test"
        hMacs.get(Algorithm.SHA256_HMAC).createEngine();   // As per IG 9.1
        hMacs.get(Algorithm.SHA512_HMAC).createEngine();
        hMacs.get(Algorithm.SHA3_256_HMAC).createEngine();
        // FSM_TRANS:3.SHS.3, "HMAC GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"HMAC Generate/Verify KAT self-test successful completion"

        // FSM_STATE:3.SHS.2,"XOF GENERATE VERIFY KAT", "The module is performing Extendable Output Function generate and verify KAT self-tests"
        // FSM_TRANS:3.SHS.3,"POWER ON SELF-TEST", "XOF GENERATE VERIFY KAT", "Invoke XOF Generate/Verify KAT self-test"
        makeValidatedXof(new Parameters(Algorithm.SHAKE256));  // As per IG A.11, Section 3
        // FSM_TRANS:3.SHS.4, "XOF GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"XOF Generate/Verify KAT self-test successful completion"

        for (Map.Entry<FipsAlgorithm, FipsEngineProvider<ExtendedDigest>> algorithm : digests.entrySet())
        {
            FipsRegister.registerEngineProvider(algorithm.getKey(), algorithm.getValue());
        }

        FipsRegister.registerEngineProvider(Algorithm.SHAKE128, new FipsEngineProvider<Xof>()
        {
            public Xof createEngine()
            {
                return makeValidatedXof(new Parameters(Algorithm.SHAKE128));
            }
        });

        FipsRegister.registerEngineProvider(Algorithm.SHAKE256, new FipsEngineProvider<Xof>()
        {
            public Xof createEngine()
            {
                return makeValidatedXof(new Parameters(Algorithm.SHAKE256));
            }
        });

        for (Map.Entry<FipsAlgorithm, FipsEngineProvider<Mac>> algorithm : hMacs.entrySet())
        {
            FipsRegister.registerEngineProvider(algorithm.getKey(), algorithm.getValue());
        }
    }

    public static final Parameters SHA1 = new Parameters(Algorithm.SHA1);
    public static final AuthParameters SHA1_HMAC = new AuthParameters(Algorithm.SHA1_HMAC);
    public static final Parameters SHA224 = new Parameters(Algorithm.SHA224);
    public static final AuthParameters SHA224_HMAC = new AuthParameters(Algorithm.SHA224_HMAC);
    public static final Parameters SHA256 = new Parameters(Algorithm.SHA256);
    public static final AuthParameters SHA256_HMAC = new AuthParameters(Algorithm.SHA256_HMAC);
    public static final Parameters SHA384 = new Parameters(Algorithm.SHA384);
    public static final AuthParameters SHA384_HMAC = new AuthParameters(Algorithm.SHA384_HMAC);
    public static final Parameters SHA512 = new Parameters(Algorithm.SHA512);
    public static final AuthParameters SHA512_HMAC = new AuthParameters(Algorithm.SHA512_HMAC);
    public static final Parameters SHA512_224 = new Parameters(Algorithm.SHA512_224);
    public static final AuthParameters SHA512_224_HMAC = new AuthParameters(Algorithm.SHA512_224_HMAC);
    public static final Parameters SHA512_256 = new Parameters(Algorithm.SHA512_256);
    public static final AuthParameters SHA512_256_HMAC = new AuthParameters(Algorithm.SHA512_256_HMAC);
    public static final Parameters SHA3_224 = new Parameters(Algorithm.SHA3_224);
    public static final AuthParameters SHA3_224_HMAC = new AuthParameters(Algorithm.SHA3_224_HMAC);
    public static final Parameters SHA3_256 = new Parameters(Algorithm.SHA3_256);
    public static final AuthParameters SHA3_256_HMAC = new AuthParameters(Algorithm.SHA3_256_HMAC);
    public static final Parameters SHA3_384 = new Parameters(Algorithm.SHA3_384);
    public static final AuthParameters SHA3_384_HMAC = new AuthParameters(Algorithm.SHA3_384_HMAC);
    public static final Parameters SHA3_512 = new Parameters(Algorithm.SHA3_512);
    public static final AuthParameters SHA3_512_HMAC = new AuthParameters(Algorithm.SHA3_512_HMAC);
    public static final Parameters SHAKE128 = new Parameters(Algorithm.SHAKE128);
    public static final Parameters SHAKE256 = new Parameters(Algorithm.SHAKE256);
    public static final CSHAKEParameters cSHAKE128 = new CSHAKEParameters(Algorithm.cSHAKE128);
    public static final CSHAKEParameters cSHAKE256 = new CSHAKEParameters(Algorithm.cSHAKE256);

    private FipsSHS()
    {
    }

    /**
     * Generic digest parameters.
     */
    public static class Parameters
        extends FipsParameters
    {
        Parameters(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Parameters for HMAC modes.
     */
    public static final class AuthParameters
        extends FipsParameters
        implements AuthenticationParameters<AuthParameters>
    {
        private final int macSizeInBits;

        private AuthParameters(FipsAlgorithm algorithm, int macSizeInBits)
        {
            super(algorithm);
            this.macSizeInBits = macSizeInBits;
        }

        AuthParameters(FipsAlgorithm algorithm)
        {
            this(algorithm, defaultMacSize.get(algorithm));
        }

        /**
         * Return the length of the MAC that will be made using these parameters in bits.
         *
         * @return the bit length of the MAC.
         */
        public int getMACSizeInBits()
        {
            return macSizeInBits;
        }

        /**
         * Return a new set of parameters specifying a specific mac size.
         *
         * @param macSizeInBits bit length of the MAC length.
         * @return a new set of AuthParameters for the MAC size.
         */
        public AuthParameters withMACSize(int macSizeInBits)
        {
            return new AuthParameters(this.getAlgorithm(), macSizeInBits);
        }
    }

    /**
     * Customizable SHAKE (cSHAKE) parameters.
     */
    public static final class CSHAKEParameters
        extends Parameters
    {
        private final byte[] functionNameString;
        private final byte[] customizationString;

        CSHAKEParameters(FipsAlgorithm algorithm)
        {
            this(algorithm, null, null);
        }

        private CSHAKEParameters(FipsAlgorithm algorithm, byte[] functionNameString, byte[] customizationString)
        {
            super(algorithm);
            this.functionNameString = functionNameString;
            this.customizationString = customizationString;
        }

        /**
         * Return a new set of parameters specifying a specific function name bit string.
         * <b>Note:</b> this parameter is reserved for use by NIST, it is best not to use it unless a
         * standard value is available.
         *
         * @param functionName the function name bit string (N).
         * @return a new set of CSHAKEParameters including the N value.
         */
        public CSHAKEParameters withFunctionName(byte[] functionName)
        {
            return new CSHAKEParameters(this.getAlgorithm(), functionName, this.customizationString);
        }

        /**
          * Return a new set of parameters specifying a specific customization string.
          *
          * @param customizationString the function name bit string (S).
          * @return a new set of CSHAKEParameters including the S value.
          */
        public CSHAKEParameters withCustomizationString(byte[] customizationString)
        {
            return new CSHAKEParameters(this.getAlgorithm(), this.functionNameString, customizationString);
        }
    }

    /**
     * Factory for producing digest calculators.
     */
    public static final class OperatorFactory<T extends Parameters>
        extends FipsDigestOperatorFactory<T>
    {
        @Override
        public FipsOutputDigestCalculator<T> createOutputDigestCalculator(T parameter)
        {
            return new LocalFipsOutputDigestCalculator<T>(parameter, createCloner(parameter.getAlgorithm()));
        }
    }

    /**
     * Factory for producing extendable output function (XOF) calculators.
     */
    public static final class XOFOperatorFactory<T extends Parameters>
        extends FipsXOFOperatorFactory<T>
    {
        @Override
        public FipsOutputXOFCalculator<T> createOutputXOFCalculator(T parameter)
        {
            return new LocalFipsOutputXOFCalculator<T>(parameter, makeValidatedXof(parameter));
        }

        private class LocalFipsOutputXOFCalculator<T extends Parameters>
            extends FipsOutputXOFCalculator
        {
            private final T parameters;
            private final XofOutputStream xofStream;

            private boolean isOutputing;

            public LocalFipsOutputXOFCalculator(T parameters, Xof xof)
            {
                this.parameters = parameters;
                this.xofStream = new XofOutputStream(xof);
            }

            @Override
            public T getParameters()
            {
                return parameters;
            }

            @Override
            public UpdateOutputStream getFunctionStream()
            {
                if (isOutputing)
                {
                    isOutputing = false;
                    xofStream.reset();
                }

                return xofStream;
            }

            @Override
            public int getFunctionOutput(byte[] output, int off, int outLen)
            {
                isOutputing = true;

                return xofStream.getOutput(output, off, outLen);
            }

            @Override
            public void reset()
            {
                xofStream.reset();
            }
        }
    }

    /**
     * HMAC key generator
     */
    public static final class KeyGenerator
        extends FipsSymmetricKeyGenerator
    {
        private final FipsAlgorithm algorithm;
        private final int keySizeInBits;
        private final SecureRandom random;

        public KeyGenerator(FipsAlgorithm algorithm, int keySizeInBits, SecureRandom random)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (keySizeInBits < MIN_APPROVED_KEY_SIZE)
                {
                    throw new IllegalArgumentException("Key size for HMAC must be at least " + MIN_APPROVED_KEY_SIZE + " bits in approved mode: " + algorithm.getName());
                }
                Utils.validateKeyGenRandom(random, MIN_APPROVED_KEY_SIZE, algorithm);
            }
            this.algorithm = algorithm;
            this.keySizeInBits = keySizeInBits;
            this.random = random;
        }

        public SymmetricKey generateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for producing HMAC calculators.
     */
    public static final class MACOperatorFactory
        extends FipsMACOperatorFactory<AuthParameters>
    {
        @Override
        protected int calculateMACSize(AuthParameters parameters)
        {
            return parameters.getMACSizeInBits() / 8;
        }

        @Override
        protected Mac createMAC(SymmetricKey key, AuthParameters parameters)
        {
            ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

            Mac mac = createHMac(parameters.getAlgorithm());
            if (mac.getMacSize() != (parameters.getMACSizeInBits() + 7) / 8)
            {
                mac = new TruncatingMac(mac, parameters.macSizeInBits);
            }

            KeyParameter keyParameter = Utils.getKeyParameter(vKey);

            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (keyParameter.getKey().length * 8 < MIN_APPROVED_KEY_SIZE)
                {
                    throw new IllegalKeyException("Key size for HMAC must be at least " + MIN_APPROVED_KEY_SIZE + " bits in approved mode: " + parameters.getAlgorithm().getName());
                }
            }

            mac.init(keyParameter);

            return mac;
        }
    }

    private interface DigestCloner<D extends ExtendedDigest>
    {
        D makeDigest(D original);
    }

    private static class LocalFipsOutputDigestCalculator<T extends Parameters>
        extends FipsOutputDigestCalculator<T>
        implements Cloneable
    {
        private final ExtendedDigest digest;
        private final T parameter;
        private final DigestCloner<ExtendedDigest> cloner;

        private LocalFipsOutputDigestCalculator(T parameter, DigestCloner<ExtendedDigest> cloner)
        {
            this(parameter, null, cloner);
        }

        private LocalFipsOutputDigestCalculator(T parameter, ExtendedDigest original, DigestCloner<ExtendedDigest> cloner)
        {
            this.digest = cloner.makeDigest(original);
            this.parameter = parameter;
            this.cloner = cloner;
        }

        @Override
        public T getParameters()
        {
            return parameter;
        }

        @Override
        public int getDigestSize()
        {
            return digest.getDigestSize();
        }

        @Override
        public int getDigestBlockSize()
        {
            return digest.getByteLength();
        }

        @Override
        public UpdateOutputStream getDigestStream()
        {
            return new DigestOutputStream(digest);
        }

        public int getDigest(byte[] output, int offSet)
        {
            return digest.doFinal(output, offSet);
        }

        @Override
        public void reset()
        {
            digest.reset();
        }

        @Override
        public FipsOutputDigestCalculator<T> clone()
            throws CloneNotSupportedException
        {
            return new LocalFipsOutputDigestCalculator<T>(parameter, digest, cloner);
        }
    }

    static DigestCloner<ExtendedDigest> createCloner(FipsAlgorithm algorithm)
    {
        switch ((Variations)algorithm.basicVariation())
        {
        case SHA1:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA1Digest((SHA1Digest)original);
                    }

                    return createDigest(Algorithm.SHA1);
                }
            };
        case SHA224:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA224Digest((SHA224Digest)original);
                    }

                    return createDigest(Algorithm.SHA224);
                }
            };
        case SHA256:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA256Digest((SHA256Digest)original);
                    }

                    return createDigest(Algorithm.SHA256);
                }
            };
        case SHA384:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA384Digest((SHA384Digest)original);
                    }

                    return createDigest(Algorithm.SHA384);
                }
            };
        case SHA512:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA512Digest((SHA512Digest)original);
                    }

                    return createDigest(Algorithm.SHA512);
                }
            };
        case SHA512_224:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA512tDigest((SHA512tDigest)original);
                    }

                    return createDigest(Algorithm.SHA512_224);
                }
            };
        case SHA512_256:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA512tDigest((SHA512tDigest)original);
                    }

                    return createDigest(Algorithm.SHA512_256);
                }
            };
        case SHA3_224:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA3Digest((SHA3Digest)original);
                    }

                    return createDigest(Algorithm.SHA3_224);
                }
            };
        case SHA3_256:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA3Digest((SHA3Digest)original);
                    }

                    return createDigest(Algorithm.SHA3_256);
                }
            };
        case SHA3_384:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA3Digest((SHA3Digest)original);
                    }

                    return createDigest(Algorithm.SHA3_384);
                }
            };
        case SHA3_512:
            return new DigestCloner<ExtendedDigest>()
            {
                public ExtendedDigest makeDigest(ExtendedDigest original)
                {
                    if (original != null)
                    {
                        return new SHA3Digest((SHA3Digest)original);
                    }

                    return createDigest(Algorithm.SHA3_512);
                }
            };
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to FipsSHS.OperatorFactory.createOutputDigestCalculator: " + algorithm.getName());
        }
    }

    static ExtendedDigest createBaseDigest(FipsAlgorithm algorithm)
    {
        switch ((Variations)algorithm.basicVariation())
        {
        case SHA1:
            return new SHA1Digest();
        case SHA224:
            return new SHA224Digest();
        case SHA256:
            return new SHA256Digest();
        case SHA384:
            return new SHA384Digest();
        case SHA512:
            return new SHA512Digest();
        case SHA512_224:
            return new SHA512tDigest(224);
        case SHA512_256:
            return new SHA512tDigest(256);
        case SHA3_224:
            return new SHA3Digest(224);
        case SHA3_256:
            return new SHA3Digest(256);
        case SHA3_384:
            return new SHA3Digest(384);
        case SHA3_512:
            return new SHA3Digest(512);
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to FipsSHS.OperatorFactory.createOutputDigestCalculator: " + algorithm.getName());
        }
    }

    private static ExtendedDigest makeValidatedDigest(FipsAlgorithm algorithm, BasicKatTest<ExtendedDigest> katTest)
    {
        return SelfTestExecutor.validate(algorithm, createBaseDigest(algorithm), katTest);
    }

    private static Xof makeValidatedXof(Parameters parameters)
    {
        FipsAlgorithm algorithm = parameters.getAlgorithm();

        if (algorithm == Algorithm.SHAKE128)
        {
            return SelfTestExecutor.validate(algorithm, new SHAKEDigest(128), new ShaKatTest<Xof>(Hex.decode("5881092dd818bf5cf8a3ddb793fbcba7")));
        }
        else if (algorithm == Algorithm.SHAKE256)
        {
            return SelfTestExecutor.validate(algorithm, new SHAKEDigest(256), new ShaKatTest<Xof>(Hex.decode("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")));
        }
        else if (algorithm == Algorithm.cSHAKE128)
        {
            CSHAKEParameters cshakeParameters = (CSHAKEParameters)parameters;

            return new CSHAKEDigest(128, cshakeParameters.functionNameString, cshakeParameters.customizationString);
        }
        else if (algorithm == Algorithm.cSHAKE256)
        {
            CSHAKEParameters cshakeParameters = (CSHAKEParameters)parameters;
            
            return new CSHAKEDigest(256, cshakeParameters.functionNameString, cshakeParameters.customizationString);
        }
        else
        {
            throw new IllegalArgumentException("Unknown extendable output function requested: " + algorithm.getName());
        }
    }

    static ExtendedDigest createDigest(FipsAlgorithm algorithm)
    {
        return digests.get(algorithm).createEngine();
    }

    private static Mac makeValidatedHMac(FipsAlgorithm algorithm, BasicKatTest<Mac> katTest)
    {
        Mac mac;
        switch ((Variations)algorithm.basicVariation())
        {
        case SHA1_HMAC:
            mac = new HMac(new SHA1Digest());
            break;
        case SHA224_HMAC:
            mac = new HMac(new SHA224Digest());
            break;
        case SHA256_HMAC:
            mac = new HMac(new SHA256Digest());
            break;
        case SHA384_HMAC:
            mac = new HMac(new SHA384Digest());
            break;
        case SHA512_HMAC:
            mac = new HMac(new SHA512Digest());
            break;
        case SHA512_224_HMAC:
            mac = new HMac(new SHA512tDigest(224));
            break;
        case SHA512_256_HMAC:
            mac = new HMac(new SHA512tDigest(256));
            break;
        case SHA3_224_HMAC:
            mac = new HMac(new SHA3Digest(224));
            break;
        case SHA3_256_HMAC:
            mac = new HMac(new SHA3Digest(256));
            break;
        case SHA3_384_HMAC:
            mac = new HMac(new SHA3Digest(384));
            break;
        case SHA3_512_HMAC:
            mac = new HMac(new SHA3Digest(512));
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to FipsSHS.OperatorFactory.createOutputMACCalculator: " + algorithm.getName());
        }

        return SelfTestExecutor.validate(algorithm, mac, katTest);
    }

    static FipsEngineProvider<Mac> getMacProvider(FipsAlgorithm algorithm)
    {
        return hMacs.get(algorithm);
    }

    static Mac createHMac(FipsAlgorithm algorithm)
    {
        return getMacProvider(algorithm).createEngine();
    }

    private static class ShaKatTest<T extends Digest>
        implements BasicKatTest<T>
    {
        private static final byte[] stdShaVector = Strings.toByteArray("abc");
        private final byte[] kat;

        ShaKatTest(byte[] kat)
        {
            this.kat = kat;
        }

        public boolean hasTestPassed(Digest digest)
        {
            digest.update(stdShaVector, 0, stdShaVector.length);

            byte[] result = new byte[digest.getDigestSize()];

            digest.doFinal(result, 0);

            digest.reset();

            return Arrays.areEqual(result, kat);
        }
    }

    private static class HMacKatTest
        implements BasicKatTest<Mac>
    {
        private static final byte[] stdHMacVector = Strings.toByteArray("what do ya want for nothing?");
        private static final byte[] key = Hex.decode("4a656665");

        private final byte[] kat;

        HMacKatTest(byte[] kat)
        {
            this.kat = kat;
        }

        public boolean hasTestPassed(Mac hMac)
        {
            hMac.init(new KeyParameterImpl(Arrays.clone(key)));

            hMac.update(stdHMacVector, 0, stdHMacVector.length);

            byte[] result = new byte[hMac.getMacSize()];

            hMac.doFinal(result, 0);

            return Arrays.areEqual(result, kat);
        }
    }
}
