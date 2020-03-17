package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.KDFOperatorFactory;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.DerivationFunction;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.EngineProvider;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.internal.modes.SICBlockCipher;
import org.bouncycastle.crypto.internal.params.KDFCounterParameters;
import org.bouncycastle.crypto.internal.params.KDFDoublePipelineIterationParameters;
import org.bouncycastle.crypto.internal.params.KDFFeedbackParameters;
import org.bouncycastle.crypto.internal.params.KDFParameters;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.crypto.internal.test.BasicKatTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for FIPS approved Key Derivation Function (KDF) implementations.
 */
public final class FipsKDF
{
    private static final byte[] ZERO_BYTE = new byte[1];

    private FipsKDF()
    {
    }

    /**
     * Algorithm parameter source for NIST SP 800-108 KDF in Counter Mode.
     */
    public static final CounterModeParametersBuilder COUNTER_MODE = new CounterModeParametersBuilder(new FipsAlgorithm("CounterMode"));

    /**
     * Algorithm parameter source for NIST SP 800-108 KDF in Feedback Mode.
     */
    public static final FeedbackModeParametersBuilder FEEDBACK_MODE = new FeedbackModeParametersBuilder(new FipsAlgorithm("FeedbackMode"));

    /**
     * Algorithm parameter source for NIST SP 800-108 KDF in Double-Pipeline Mode.
     */
    public static final DoublePipelineModeParametersBuilder DOUBLE_PIPELINE_ITERATION_MODE = new DoublePipelineModeParametersBuilder(new FipsAlgorithm("DoublePipelineIterationMode"));

    /**
     * Algorithm parameter source for Secure Shell (SSH)
     */
    public static final SSHParametersBuilder SSH = new SSHParametersBuilder(new FipsAlgorithm("SSH"), SSHPRF.SHA1);

    /**
     * Algorithm parameter source for Internet Key Exchange Version 2 (IKEv2)
     */
    public static final IKEv2ParametersBuilder IKEv2 = new IKEv2ParametersBuilder(new FipsAlgorithm("IKEv2"), IKEv2PRF.SHA1);

    /**
     * Algorithm parameter source for Secure Real-time Transport Protocol (SRTP)
     */
    public static final SRTPParametersBuilder SRTP = new SRTPParametersBuilder(new FipsAlgorithm("SRTP"), SRTPPRF.AES_CM);

    /**
     * Algorithm parameter source for Transport Layer Security Version 1.0 (TLSv1.0)
     */
    public static final TLSParametersBuilder TLS1_0 = new TLSParametersBuilder(new FipsAlgorithm("TLS1.0"));

    /**
     * Algorithm parameter source for Transport Layer Security Version 1.1 (TLSv1.1)
     */
    public static final TLSParametersBuilder TLS1_1 = new TLSParametersBuilder(new FipsAlgorithm("TLS1.1"));

    /**
     * Algorithm parameter source for Transport Layer Security Version 1.2 (TLSv1.2)
     */
    public static final TLSParametersWithPRFBuilder TLS1_2 = new TLSParametersWithPRFBuilder(new FipsAlgorithm("TLS1.2"), TLSPRF.SHA256_HMAC);

    /**
     * Algorithm parameter source for ASN X9.63-2001 - default PRF is SHA-1
     */
    public static final AgreementKDFParametersBuilder X963 = new AgreementKDFParametersBuilder(new FipsAlgorithm("X9.63"), AgreementKDFPRF.SHA1);

    /**
     * Algorithm parameter source for concatenating KDF in FIPS SP 800-56A/B - default PRF is SHA-1
     */
    public static final AgreementKDFParametersBuilder CONCATENATION = new AgreementKDFParametersBuilder(new FipsAlgorithm("Concatenation"), AgreementKDFPRF.SHA1);

    /**
     * An enumeration of the FIPS approved psuedo-random-function (PRF) for KDFs used with SP 800-108.
     */
    public enum PRF {
        AES_CMAC(FipsAES.CMAC.getAlgorithm()),
        TRIPLEDES_CMAC(FipsTripleDES.CMAC.getAlgorithm()),
        SHA1_HMAC(FipsSHS.Algorithm.SHA1_HMAC),
        SHA224_HMAC(FipsSHS.Algorithm.SHA224_HMAC),
        SHA256_HMAC(FipsSHS.Algorithm.SHA256_HMAC),
        SHA384_HMAC(FipsSHS.Algorithm.SHA384_HMAC),
        SHA512_HMAC(FipsSHS.Algorithm.SHA512_HMAC),
        SHA512_224_HMAC(FipsSHS.Algorithm.SHA512_224_HMAC),
        SHA512_256_HMAC(FipsSHS.Algorithm.SHA512_256_HMAC);

        private final FipsAlgorithm algorithm;

        PRF(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public FipsAlgorithm getAlgorithm()
        {
            return algorithm;
        }
    }

    static
    {
        // FSM_STATE:3.KBKDF.0,"KBKDF GENERATE KAT", "The module is performing KBKDF generate KAT self-test"
        // FSM_TRANS:3.KBKDF.0,"POWER ON SELF-TEST", "PBKDF GENERATE KAT",	"Invoke KBKDF Generate KAT self-test"
        new CounterModeProvider(PRF.AES_CMAC).createEngine();
        new CounterModeProvider(PRF.TRIPLEDES_CMAC).createEngine();
        new CounterModeProvider(PRF.SHA1_HMAC).createEngine();
        new CounterModeProvider(PRF.SHA224_HMAC).createEngine();
        new CounterModeProvider(PRF.SHA256_HMAC).createEngine();
        new CounterModeProvider(PRF.SHA384_HMAC).createEngine();
        new CounterModeProvider(PRF.SHA512_HMAC).createEngine();
        new CounterModeProvider(PRF.SHA512_224_HMAC).createEngine();
        new CounterModeProvider(PRF.SHA512_256_HMAC).createEngine();

        new FeedbackModeProvider(PRF.AES_CMAC).createEngine();
        new FeedbackModeProvider(PRF.TRIPLEDES_CMAC).createEngine();
        new FeedbackModeProvider(PRF.SHA1_HMAC).createEngine();
        new FeedbackModeProvider(PRF.SHA224_HMAC).createEngine();
        new FeedbackModeProvider(PRF.SHA256_HMAC).createEngine();
        new FeedbackModeProvider(PRF.SHA384_HMAC).createEngine();
        new FeedbackModeProvider(PRF.SHA512_HMAC).createEngine();
        new FeedbackModeProvider(PRF.SHA512_224_HMAC).createEngine();
        new FeedbackModeProvider(PRF.SHA512_256_HMAC).createEngine();

        new DoublePipelineModeProvider(PRF.AES_CMAC).createEngine();
        new DoublePipelineModeProvider(PRF.TRIPLEDES_CMAC).createEngine();
        new DoublePipelineModeProvider(PRF.SHA1_HMAC).createEngine();
        new DoublePipelineModeProvider(PRF.SHA224_HMAC).createEngine();
        new DoublePipelineModeProvider(PRF.SHA256_HMAC).createEngine();
        new DoublePipelineModeProvider(PRF.SHA384_HMAC).createEngine();
        new DoublePipelineModeProvider(PRF.SHA512_HMAC).createEngine();
        new DoublePipelineModeProvider(PRF.SHA512_224_HMAC).createEngine();
        new DoublePipelineModeProvider(PRF.SHA512_256_HMAC).createEngine();
        // FSM_TRANS:3.KBKDF.1, "KBKDF GENERATE KAT", "POWER ON SELF-TEST", "KBKDF Generate KAT self-test successful completion"
    }

    /**
     * Parameters for the Counter Mode parameters builder.
     */
    public static final class CounterModeParametersBuilder
        extends FipsParameters
    {
        private final PRF prf;
        private final int r;

        CounterModeParametersBuilder(FipsAlgorithm algorithm)
        {
            this(algorithm, PRF.SHA1_HMAC, 8);
        }

        private CounterModeParametersBuilder(FipsAlgorithm algorithm, PRF prf, int r)
        {
            super(algorithm);
            this.prf = prf;
            this.r = r;
        }

        /**
         * Return a new parameters builder based around the passed in PRF and counter size.
         *
         * @param prf the PRF to be used in the final KDF.
         * @param r the length in bits of the counter to be used.
         * @return a new parameters builder.
         */
        public CounterModeParametersBuilder withPRFAndR(PRF prf, int r)
        {
            return new CounterModeParametersBuilder(getAlgorithm(), prf, r);
        }

        /**
         * Return a new parameter set for ki and a prefix.
         *
         * @param ki derivation key for the KDF.
         * @param fixedInputPrefix prefix data to come before the counter during calculation.
         * @return a CounterModeParameters object.
         */
        public CounterModeParameters using(byte[] ki, byte[] fixedInputPrefix)
        {
            return new CounterModeParameters(new FipsAlgorithm(getAlgorithm(), prf), r, Arrays.clone(ki), Arrays.clone(fixedInputPrefix), null);
        }

        /**
         * Return a new parameter set for ki and the prefix/suffix data.
         *
         * @param ki derivation key for the KDF.
         * @param fixedInputPrefix prefix data to come before the counter during calculation.
         * @param fixedInputSuffix suffix data to come after the counter during calculation.
         * @return a CounterModeParameters object.
         */
        public CounterModeParameters using(byte[] ki, byte[] fixedInputPrefix, byte[] fixedInputSuffix)
        {
            return new CounterModeParameters(new FipsAlgorithm(getAlgorithm(), prf), r, Arrays.clone(ki), Arrays.clone(fixedInputPrefix), Arrays.clone(fixedInputSuffix));
        }

        /**
         * Build method for parameters which builds fixed input as outlined in SP 800-108 with the fixed input
         * as a prefix, or suffix, to the counter.
         *
         * @param ki  input key.
         * @param isPrefix is the fixed input a prefix or a suffix.
         * @param label label - fixed input component.
         * @param context context - fixed input component.
         * @param L number of bits per request for the KDF these parameters will initialise - fixed input component.
         * @return a CounterModeParameters object.
         */
        public CounterModeParameters using(byte[] ki, boolean isPrefix, byte[] label, byte[] context, int L)
        {
            return new CounterModeParameters(new FipsAlgorithm(getAlgorithm(), prf), r, Arrays.clone(ki), (isPrefix ? buildFixedInput(label, context, L) : null), (isPrefix ? null : buildFixedInput(label, context, L)));
        }
    }

    /**
     * Parameters for the Counter Mode key derivation function.
     */
    public static final class CounterModeParameters
        extends FipsParameters
    {
        final int r;
        final byte[] ki;
        final byte[] fixedInputPrefix;
        final byte[] fixedInputSuffix;

        private CounterModeParameters(FipsAlgorithm algorithm, int r, byte[] ki, byte[] fixedInputPrefix, byte[] fixedInputSuffix)
        {
            super(algorithm);

            this.r = r;
            this.ki = ki;
            this.fixedInputPrefix = fixedInputPrefix;
            this.fixedInputSuffix = fixedInputSuffix;
        }
    }

    /**
     * Factory for Counter Mode KDFs.
     */
    public static final class CounterModeFactory
        extends FipsKDFOperatorFactory<CounterModeParameters>
    {
        public CounterModeFactory()
        {
        }

        public KDFCalculator<CounterModeParameters> createKDFCalculator(final CounterModeParameters params)
        {
            Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

            final KDFCounterBytesGenerator kdfGenerator = new CounterModeProvider(params.getAlgorithm()).createEngine();

            kdfGenerator.init(new KDFCounterParameters(params.ki, params.fixedInputPrefix, params.fixedInputSuffix, params.r));

            return new MonitoringKDFCalculator<CounterModeParameters>(approvedModeOnly, new BaseKDFCalculator<CounterModeParameters>()
            {
                public CounterModeParameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    kdfGenerator.generateBytes(out, outOff, len);
                }
            });
        }
    }

    /**
     * An enumeration of the counter locations for Feedback Mode and Double Pipeline Iteration Mode.
     */
    public enum CounterLocation
    {
        AFTER_ITERATION_DATA(KDFFeedbackParameters.AFTER_ITER),
        AFTER_FIXED_INPUT(KDFFeedbackParameters.AFTER_FIXED),
        BEFORE_ITERATION_DATA(KDFFeedbackParameters.BEFORE_ITER);

        private final int code;

        CounterLocation(int code)
        {
            this.code = code;
        }
    }

    /**
     * Parameters for the Feedback Mode parameters builder.
     */
    public static final class FeedbackModeParametersBuilder
        extends FipsParameters
    {
        private final PRF prf;
        private final int r;
        private final CounterLocation counterLocation;

        FeedbackModeParametersBuilder(FipsAlgorithm algorithm)
        {
            this(algorithm, PRF.SHA1_HMAC, -1, null);
        }

        private FeedbackModeParametersBuilder(FipsAlgorithm algorithm, PRF prf, int r, CounterLocation counterLocation)
        {
            super(algorithm);
            this.prf = prf;
            this.r = r;
            this.counterLocation = counterLocation;
        }

        /**
         * Return a new parameters builder based around the passed in PRF.
         *
         * @param prf the PRF to be used in the final KDF.
         * @return a new parameters builder.
         */
        public FeedbackModeParametersBuilder withPRF(PRF prf)
        {
            return new FeedbackModeParametersBuilder(getAlgorithm(), prf, -1, null);
        }

        /**
         * Return a new parameters builder based around the passed in counter size. The
         * counter will be after the iteration data.
         *
         * @param r the length in bits of the counter to be used.
         * @return a new parameters builder.
         */
        public FeedbackModeParametersBuilder withR(int r)
        {
            return new FeedbackModeParametersBuilder(getAlgorithm(), prf, r, CounterLocation.AFTER_ITERATION_DATA);
        }

        /**
         * Return a new parameters builder based around the passed in counter size and counter position.
         *
         * @param r the length in bits of the counter to be used.
         * @param counterLocation the location of the counter in data passed to the PRF during calculation.
         * @return a new parameters builder.
         */
        public FeedbackModeParametersBuilder withRAndLocation(int r, CounterLocation counterLocation)
        {
            return new FeedbackModeParametersBuilder(getAlgorithm(), prf, r, counterLocation);
        }

        /**
         * Return a new parameter set for ki and a prefix.
         *
         * @param ki derivation key for the KDF.
         * @param iv the IV to use at the start of the calculation.
         * @param fixedInputData fixed input data to use in calculation.
         * @return a FeedbackModeParameters object.
         */
        public FeedbackModeParameters using(byte[] ki, byte[] iv, byte[] fixedInputData)
        {
            return new FeedbackModeParameters(new FipsAlgorithm(getAlgorithm(), prf), r, counterLocation, Arrays.clone(ki), Arrays.clone(iv), Arrays.clone(fixedInputData));
        }

        /**
         * Build method for parameters which builds fixed input as outlined in SP 800-108 with the fixed input
         * as a prefix, or suffix, to the counter.
         *
         * @param ki  input key.
         * @param iv  initialization vector.
         * @param label label - fixed input component.
         * @param context context - fixed input component.
         * @param L number of bits per request for the KDF these parameters will initialise - fixed input component.
         * @return a FeedbackModeParameters object.
         */
        public FeedbackModeParameters using(byte[] ki, byte[] iv, byte[] label, byte[] context, int L)
        {
            return new FeedbackModeParameters(new FipsAlgorithm(getAlgorithm(), prf), r, counterLocation, Arrays.clone(ki), Arrays.clone(iv), buildFixedInput(label, context, L));
        }
    }

    /**
     * Parameters for the Feedback Mode key derivation function.
     */
    public static final class FeedbackModeParameters
        extends FipsParameters
    {
        private final int r;
        private final CounterLocation counterLocation;
        private final byte[] ki;
        private final byte[] iv;
        private final byte[] fixedInputData;

        private FeedbackModeParameters(FipsAlgorithm algorithm, int r, CounterLocation counterLocation, byte[] ki, byte[] iv, byte[] fixedInputData)
        {
            super(algorithm);

            this.r = r;
            this.counterLocation = counterLocation;
            this.ki = ki;
            this.iv = iv;
            this.fixedInputData = fixedInputData;
        }
    }

    /**
     * Factory for Feedback Mode KDFs.
     */
    public static final class FeedbackModeFactory
        extends FipsKDFOperatorFactory<FeedbackModeParameters>
    {
        public FeedbackModeFactory()
        {
        }

        public KDFCalculator<FeedbackModeParameters> createKDFCalculator(final FeedbackModeParameters params)
        {
            Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

            final KDFFeedbackBytesGenerator kdfGenerator = new FeedbackModeProvider(params.getAlgorithm()).createEngine();
            CounterLocation counterLocation = params.counterLocation;
            int r = params.r;

            if (r > 0)
            {
                kdfGenerator.init(KDFFeedbackParameters.createWithCounter(counterLocation.code, params.ki, params.iv, params.fixedInputData, r));
            }
            else
            {
                kdfGenerator.init(KDFFeedbackParameters.createWithoutCounter(params.ki, params.iv, params.fixedInputData));
            }

            return new MonitoringKDFCalculator<FeedbackModeParameters>(approvedModeOnly, new BaseKDFCalculator<FeedbackModeParameters>()
            {
                public FeedbackModeParameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    kdfGenerator.generateBytes(out, outOff, len);
                }
            });
        }
    }

    /**
     * Parameters for the Double Pipeline Mode parameters builder.
     */
    public static final class DoublePipelineModeParametersBuilder
        extends FipsParameters
    {
        private final PRF prf;
        private final int r;
        private final CounterLocation counterLocation;

        DoublePipelineModeParametersBuilder(FipsAlgorithm algorithm)
        {
            this(algorithm, PRF.SHA1_HMAC, -1, null);
        }

        private DoublePipelineModeParametersBuilder(FipsAlgorithm algorithm, PRF prf, int r, CounterLocation counterLocation)
        {
            super(algorithm);
            this.prf = prf;
            this.r = r;
            this.counterLocation = counterLocation;
        }

        /**
         * Return a new parameters builder based around the passed in PRF.
         *
         * @param prf the PRF to be used in the final KDF.
         * @return a new parameters builder.
         */
        public DoublePipelineModeParametersBuilder withPRF(PRF prf)
        {
            return new DoublePipelineModeParametersBuilder(getAlgorithm(), prf, -1, null);
        }

        /**
         * Return a new parameters builder based around the passed in counter size. The
         * counter will be after the iteration data.
         *
         * @param r the length in bits of the counter to be used.
         * @return a new parameters builder.
         */
        public DoublePipelineModeParametersBuilder withR(int r)
        {
            return new DoublePipelineModeParametersBuilder(getAlgorithm(), prf, r, CounterLocation.AFTER_ITERATION_DATA);
        }

        /**
         * Return a new parameters builder based around the passed in counter size and counter position.
         *
         * @param r the length in bits of the counter to be used.
         * @param counterLocation the location of the counter in data passed to the PRF during calculation.
         * @return a new parameters builder.
         */
        public DoublePipelineModeParametersBuilder withRAndLocation(int r, CounterLocation counterLocation)
        {
            return new DoublePipelineModeParametersBuilder(getAlgorithm(), prf, r, counterLocation);
        }

        /**
         * Return a new parameter set for ki and a prefix.
         *
         * @param ki derivation key for the KDF.
         * @param fixedInputData fixed input data to use in calculation.
         * @return a DoublePipelineModeParameters object.
         */
        public DoublePipelineModeParameters using(byte[] ki, byte[] fixedInputData)
        {
            return new DoublePipelineModeParameters(new FipsAlgorithm(getAlgorithm(), prf), r, counterLocation, Arrays.clone(ki), Arrays.clone(fixedInputData));
        }

        /**
         * Build method for parameters which builds fixed input as outlined in SP 800-108 with the fixed input
         * as a prefix, or suffix, to the counter.
         *
         * @param ki  input key.
         * @param label label - fixed input component.
         * @param context context - fixed input component.
         * @param L number of bits per request for the KDF these parameters will initialise - fixed input component.
         * @return a DoublePipelineModeParameters object.
         */
        public DoublePipelineModeParameters using(byte[] ki, byte[] label, byte[] context, int L)
        {
            return new DoublePipelineModeParameters(new FipsAlgorithm(getAlgorithm(), prf), r, counterLocation, Arrays.clone(ki), buildFixedInput(label, context, L));
        }
    }

    /**
     * Parameters for the Double Pipeline Mode key derivation function.
     */
    public static final class DoublePipelineModeParameters
        extends FipsParameters
    {
        private final int r;
        private final CounterLocation counterLocation;
        private final byte[] ki;
        private final byte[] fixedInputData;

        private DoublePipelineModeParameters(FipsAlgorithm algorithm, int r, CounterLocation counterLocation, byte[] ki, byte[] fixedInputData)
        {
            super(algorithm);

            this.r = r;
            this.counterLocation = counterLocation;
            this.ki = ki;
            this.fixedInputData = fixedInputData;
        }
    }

    /**
     * Factory for Double Pipeline Iteration Mode KDF.
     */
    public static final class DoublePipelineModeFactory
        extends FipsKDFOperatorFactory<DoublePipelineModeParameters>
    {
        public DoublePipelineModeFactory()
        {

        }

        public KDFCalculator<DoublePipelineModeParameters> createKDFCalculator(final DoublePipelineModeParameters params)
        {
            Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

            final KDFDoublePipelineIterationBytesGenerator kdfGenerator = new DoublePipelineModeProvider(params.getAlgorithm()).createEngine();
            CounterLocation counterLocation = params.counterLocation;
            int r = params.r;

            if (r > 0)
            {
                kdfGenerator.init(KDFDoublePipelineIterationParameters.createWithCounter(counterLocation.code, params.ki, params.fixedInputData, r));
            }
            else
            {
                kdfGenerator.init(KDFDoublePipelineIterationParameters.createWithoutCounter(params.ki, params.fixedInputData));
            }

            return new MonitoringKDFCalculator<DoublePipelineModeParameters>(approvedModeOnly, new BaseKDFCalculator<DoublePipelineModeParameters>()
            {
                public DoublePipelineModeParameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    kdfGenerator.generateBytes(out, outOff, len);
                }
            });
        }
    }

    private static byte[] buildFixedInput(byte[] label, byte[] context, int L)
    {
        return Arrays.concatenate(label, ZERO_BYTE, context, Pack.intToBigEndian(L));
    }

    private static FipsEngineProvider<Mac> createPRF(PRF prfAlgorithm)
    {
        FipsEngineProvider<Mac> macProvider;
        if (prfAlgorithm == PRF.TRIPLEDES_CMAC)
        {
            macProvider = FipsTripleDES.getMacProvider(FipsTripleDES.CMAC.getAlgorithm());
        }
        else if (prfAlgorithm == PRF.AES_CMAC)
        {
            macProvider = FipsAES.getMacProvider(FipsAES.CMAC.getAlgorithm());
        }
        else
        {
            macProvider = FipsSHS.getMacProvider(prfAlgorithm.algorithm);
        }

        if (macProvider == null)
        {
            throw new IllegalArgumentException("Unknown algorithm passed to FipsKDF.createPRF: " + prfAlgorithm);
        }

        return macProvider;
    }

    static byte[] processZBytes(byte[] zBytes, FipsAgreementParameters parameters)
    {
        PRF prfMacAlg = parameters.getPrfAlgorithm();
        byte[] salt = parameters.salt;
        FipsAlgorithm digestAlg = parameters.digestAlgorithm;
        KDFOperatorFactory<FipsKDF.AgreementKDFParameters> kdfOperatorFactory = new FipsKDF.AgreementOperatorFactory();
        FipsKDF.AgreementKDFParametersBuilder kdfType = parameters.kdfType;

        if (prfMacAlg == PRF.TRIPLEDES_CMAC && CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Requested PRF has insufficient security level for approved mode: " + prfMacAlg.name());
        }

        if (prfMacAlg != null)
        {
            final Mac prfMac = FipsKDF.createPRF(prfMacAlg).createEngine();

            if (salt == null)
            {
                if (prfMac instanceof HMac)
                {
                    prfMac.init(new KeyParameterImpl(new byte[((HMac)prfMac).getUnderlyingDigest().getByteLength()]));
                }
                else
                {
                    prfMac.init(new KeyParameterImpl(new byte[16]));
                }
            }
            else
            {
                prfMac.init(new KeyParameterImpl(Arrays.clone(salt)));
            }

            byte[] mac = new byte[prfMac.getMacSize()];

            prfMac.update(zBytes, 0, zBytes.length);

            prfMac.doFinal(mac, 0);

            // ZEROIZE
            Arrays.fill(zBytes, (byte)0);

            return mac;
        }
        else if (digestAlg != null)
        {
            Digest digest = FipsSHS.createDigest(digestAlg);

            byte[] hash = new byte[digest.getDigestSize()];

            digest.update(zBytes, 0, zBytes.length);

            digest.doFinal(hash, 0);

            // ZEROIZE
            Arrays.fill(zBytes, (byte)0);

            return hash;
        }
        else if (kdfType != null)
        {
            KDFCalculator kdfCalculator = kdfOperatorFactory.createKDFCalculator(kdfType.using(zBytes).withIV(salt));

            Arrays.fill(zBytes, (byte)0);

            byte[] rv = new byte[parameters.outputSize];

            kdfCalculator.generateBytes(rv);

            return rv;
        }
        else
        {
            return zBytes;
        }
    }

    /**
     * An enumeration of the FIPS approved psuedo-random-function (PRF) for KDFs used with TLS.
     */
    public enum TLSPRF {
        SHA256_HMAC(FipsSHS.Algorithm.SHA256_HMAC),
        SHA384_HMAC(FipsSHS.Algorithm.SHA384_HMAC),
        SHA512_HMAC(FipsSHS.Algorithm.SHA512_HMAC);

        private final FipsAlgorithm algorithm;

        TLSPRF(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public FipsAlgorithm getAlgorithm()
        {
            return algorithm;
        }
    }

    /**
     * The standard string values for TLS key calculation stages.
     */
    public static final class TLSStage
    {
        private TLSStage()
        {

        }

        public static final String MASTER_SECRET = "master secret";
        public static final String KEY_EXPANSION = "key expansion";
        public static final String EXTENDED_MASTER_SECRET = "extended master secret";
    }

    /**
     * Parameter builder for TLS 1.0/1.1
     */
    public static class TLSParametersBuilder
        extends FipsParameters
    {
        TLSParametersBuilder(FipsAlgorithm algorithm)
        {
            super(algorithm);
        }

        /**
          * Create parameters for a version TLS 1.0/1.1 KDF
          *
          * @param secret secret to use
          * @param label e.g. 'master secret', or 'key expansion'
          * @param seedMaterial one or more byte arrays making up the seed
          */
        public TLSParameters using(byte[] secret, String label, byte[]... seedMaterial)
        {
            return new TLSParameters(getAlgorithm(), Arrays.clone(secret), label, Arrays.concatenate(seedMaterial));
        }
    }

    /**
     * Parameter builder for TLS 1.2
     */
    public static final class TLSParametersWithPRFBuilder
        extends TLSParametersBuilder
    {
        private final TLSPRF prf;

        TLSParametersWithPRFBuilder(FipsAlgorithm algorithm, TLSPRF prf)
        {
            super(algorithm);
            this.prf = prf;
        }

        public TLSParametersWithPRFBuilder withPRF(TLSPRF prf)
        {
            return new TLSParametersWithPRFBuilder(getAlgorithm(), prf);
        }

        /**
         * Create parameters for a version TLS 1.2 KDF.
         *
         * @param secret secret to use
         * @param label e.g. 'master secret', or 'key expansion'
         * @param seedMaterial one or more byte arrays making up the seed
         */
        public TLSParameters using(byte[] secret, String label, byte[]... seedMaterial)
        {
            return new TLSParameters(new FipsAlgorithm(getAlgorithm(), prf), Arrays.clone(secret), label, Arrays.concatenate(seedMaterial));
        }
    }

    /**
     * Parameters for the TLS key derivation functions.
     */
    public static final class TLSParameters
        extends FipsParameters
    {
        private final byte[] secret;
        private final String label;
        private final byte[] seed;

        /**
         * Constructor specifying which version of TLS the KDF should be for.
         *
         * @param version TLS version this is for.
         * @param secret secret to use
         * @param label e.g. 'master secret', or 'key expansion'
         * @param seed the seed material
         */
        TLSParameters(FipsAlgorithm version, byte[] secret, String label,  byte[] seed)
        {
            super(version);

            this.secret = secret;
            this.label = label;
            this.seed = seed;
        }
    }

    /**
     * Factory for operators that derive key material using the TLS family of KDFs.
     */
    public static final class TLSOperatorFactory
        extends FipsKDFOperatorFactory<TLSParameters>
    {
        /**
         * Create the operator factory.
         */
        public TLSOperatorFactory()
        {

        }

        public KDFCalculator<TLSParameters> createKDFCalculator(final TLSParameters params)
        {
            final TLSPRF prfAlgorithm = (TLSPRF)params.getAlgorithm().basicVariation();

            Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

            if (prfAlgorithm == null)
            {
                final Mac md5Hmac = new HMac(md5Provider.createEngine());
                final Mac sha1HMac = FipsSHS.createHMac(FipsSHS.Algorithm.SHA1_HMAC);

                return new MonitoringKDFCalculator<TLSParameters>(approvedModeOnly, new BaseKDFCalculator<TLSParameters>()
                {
                    public TLSParameters getParameters()
                    {
                        return params;
                    }

                    public void generateBytes(byte[] out, int outOff, int len)
                    {
                        byte[] tmp = PRF_legacy(params, params.secret, params.label, len, md5Hmac, sha1HMac);

                        System.arraycopy(tmp, 0, out, outOff, len);
                    }
                });
            }

            return new MonitoringKDFCalculator<TLSParameters>(approvedModeOnly, new BaseKDFCalculator<TLSParameters>()
            {
                public TLSParameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    byte[] tmp = PRF(params, prfAlgorithm, params.secret, params.label, len);

                    System.arraycopy(tmp, 0, out, outOff, len);
                }
            });
        }
    }

    private static byte[] PRF(TLSParameters parameters, TLSPRF prfAlgorithm, byte[] secret, String asciiLabel, int size)
    {
        byte[] label = Strings.toByteArray(asciiLabel);
        byte[] labelSeed = Arrays.concatenate(label, parameters.seed);

        Mac prfMac = FipsSHS.createHMac(prfAlgorithm.algorithm);
        byte[] buf = new byte[size];
        hmac_hash(prfMac, secret, labelSeed, buf);
        return buf;
    }

    private static byte[] PRF_legacy(TLSParameters parameters, byte[] secret, String asciiLabel, int size, Mac md5Hmac, Mac sha1HMac)
    {
        byte[] label = Strings.toByteArray(asciiLabel);
        byte[] labelSeed = Arrays.concatenate(label, parameters.seed);

        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[size];
        byte[] b2 = new byte[size];
        hmac_hash(md5Hmac, s1, labelSeed, b1);
        hmac_hash(sha1HMac, s2, labelSeed, b2);
        for (int i = 0; i < size; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    private static void hmac_hash(Mac mac, byte[] secret, byte[] seed, byte[] out)
    {
        mac.init(new KeyParameterImpl(secret));
        byte[] a = seed;
        int size = mac.getMacSize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getMacSize()];
        byte[] buf2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.update(a, 0, a.length);
            mac.doFinal(buf, 0);
            a = buf;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(buf2, 0);
            System.arraycopy(buf2, 0, out, (size * i), Math.min(size, out.length - (size * i)));
        }
    }

    /**
     * An enumeration of the FIPS approved psuedo-random-function (PRF) for KDFs used with SSH key exchange.
     */
    public enum SSHPRF {
        SHA1(FipsSHS.Algorithm.SHA1),
        SHA224(FipsSHS.Algorithm.SHA224),
        SHA256(FipsSHS.Algorithm.SHA256),
        SHA384(FipsSHS.Algorithm.SHA384),
        SHA512(FipsSHS.Algorithm.SHA512);

        private final FipsAlgorithm algorithm;

        SSHPRF(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public FipsAlgorithm getAlgorithm()
        {
            return algorithm;
        }
    }

    /**
     * Parameters builder for the SSH key derivation function.
     */
    public static final class SSHParametersBuilder
        extends FipsParameters
    {
        SSHPRF prf;

        SSHParametersBuilder(FipsAlgorithm algorithm, SSHPRF prf)
        {
            super(algorithm);
            this.prf = prf;
        }

        public SSHParametersBuilder withPRF(SSHPRF prf)
        {
            return new SSHParametersBuilder(getAlgorithm(), prf);
        }

        public SSHParameters using(char x, byte[] sharedKey, byte[] exchangeHash, byte[] sessionID)
        {
            return new SSHParameters(new FipsAlgorithm(getAlgorithm(), prf), x, Arrays.clone(sharedKey), Arrays.clone(exchangeHash), Arrays.clone(sessionID));
        }

        public SSHPRF getPRF()
        {
            return prf;
        }
    }

    /**
     * Parameters for the SSH key derivation function.
     */
    public static final class SSHParameters
        extends FipsParameters
    {
        private final char x;
        private final byte[] sharedKey;
        private final byte[] exchangeHash;
        private final byte[] sessionID;

        /**
         * Base constructor. Create parameters for a SSH KDF.
         *
         */
        SSHParameters(FipsAlgorithm algorithm, char x, byte[] sharedKey, byte[] exchangeHash, byte[] sessionID)
        {
            super(algorithm);

            this.x = x;
            this.sharedKey = sharedKey;
            this.exchangeHash = exchangeHash;
            this.sessionID = sessionID;
        }

        SSHParameters(SSHParameters params, SSHPRF prfAlgorithm)
        {
            this(new FipsAlgorithm(params.getAlgorithm(), prfAlgorithm), params.x, params.sharedKey, params.exchangeHash, params.sessionID);
        }

        public SSHParameters withX(char x)
        {
            return new SSHParameters(this.getAlgorithm(), x, this.sharedKey, this.exchangeHash, this.sessionID);
        }
    }

    /**
     * Factory for operators that derive key material using the SSH KDF.
     */
    public static final class SSHOperatorFactory
        extends FipsKDFOperatorFactory<SSHParameters>
    {
        public SSHOperatorFactory()
        {
        }

        public KDFCalculator<SSHParameters> createKDFCalculator(final SSHParameters params)
        {
            Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

            final Digest digest = FipsSHS.createDigest(((SSHPRF)params.getAlgorithm().basicVariation()).algorithm);

            return new MonitoringKDFCalculator<SSHParameters>(approvedModeOnly, new BaseKDFCalculator<SSHParameters>()
            {
                public SSHParameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    hash(digest, params, out, outOff, len);
                }
            });
        }

        /*
           -  Initial IV client to server: HASH(K || H || "A" || session_id)
              (Here K is encoded as mpint and "A" as byte and session_id as raw
              data.  "A" means the single character A, ASCII 65).

           -  Initial IV server to client: HASH(K || H || "B" || session_id)

           -  Encryption key client to server: HASH(K || H || "C" || session_id)

           -  Encryption key server to client: HASH(K || H || "D" || session_id)

           -  Integrity key client to server: HASH(K || H || "E" || session_id)

           -  Integrity key server to client: HASH(K || H || "F" || session_id)


              K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
              K2 = HASH(K || H || K1)
              K3 = HASH(K || H || K1 || K2)
              ...
              key = K1 || K2 || K3 || ...
         */
        private static void hash(Digest digest, SSHParameters params, byte[] out, int outOff, int len)
        {
            int size = digest.getDigestSize();
            int iterations = (len + size - 1) / size;
            byte[] buf = new byte[digest.getDigestSize()];

            digest.update(params.sharedKey, 0, params.sharedKey.length);
            digest.update(params.exchangeHash, 0, params.exchangeHash.length);
            digest.update((byte)params.x);
            digest.update(params.sessionID, 0, params.sessionID.length);

            digest.doFinal(buf, 0);

            System.arraycopy(buf, 0, out, outOff, Math.min(size, len));

            for (int i = 1; i < iterations; i++)
            {
                digest.update(params.sharedKey, 0, params.sharedKey.length);
                digest.update(params.exchangeHash, 0, params.exchangeHash.length);
                digest.update(out, outOff, size * i);

                digest.doFinal(buf, 0);

                System.arraycopy(buf, 0, out, outOff + (size * i), Math.min(size, out.length - (size * i)));
            }
        }
    }

    /**
     * An enumeration of the FIPS approved psuedo-random-function (PRF) for KDFs used with key agreement.
     */
    public enum AgreementKDFPRF
    {
        SHA1(FipsSHS.Algorithm.SHA1),
        SHA224(FipsSHS.Algorithm.SHA224),
        SHA256(FipsSHS.Algorithm.SHA256),
        SHA384(FipsSHS.Algorithm.SHA384),
        SHA512(FipsSHS.Algorithm.SHA512),
        SHA512_224(FipsSHS.Algorithm.SHA512_224),
        SHA512_256(FipsSHS.Algorithm.SHA512_256),
        SHA3_224(FipsSHS.Algorithm.SHA3_224),
        SHA3_256(FipsSHS.Algorithm.SHA3_256),
        SHA3_384(FipsSHS.Algorithm.SHA3_384),
        SHA3_512(FipsSHS.Algorithm.SHA3_512);

        private final FipsAlgorithm algorithm;

        AgreementKDFPRF(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public FipsAlgorithm getAlgorithm()
        {
            return algorithm;
        }
    }

    /**
     * Parameters builder for the X9.63 and CONCATENATION key derivation function.
     */
    public static final class AgreementKDFParametersBuilder
        extends FipsParameters
    {
        AgreementKDFPRF prf;

        AgreementKDFParametersBuilder(FipsAlgorithm algorithm, AgreementKDFPRF prf)
        {
            super(algorithm);
            this.prf = prf;
        }

        public AgreementKDFParametersBuilder withPRF(AgreementKDFPRF prf)
        {
            return new AgreementKDFParametersBuilder(getAlgorithm(), prf);
        }

        public AgreementKDFParameters using(byte[] shared)
        {
            return new AgreementKDFParameters(new FipsAlgorithm(getAlgorithm(), prf), Arrays.clone(shared));
        }

        public AgreementKDFPRF getPRF()
        {
            return prf;
        }
    }

    /**
     * Parameters for the X9.63 and CONCATENATION key derivation function.
     */
    public static final class AgreementKDFParameters
        extends FipsParameters
    {
        private final byte[] shared;
        private final byte[] iv;

        AgreementKDFParameters(FipsAlgorithm algorithm, byte[] shared)
        {
            this(algorithm, shared, null);
        }

        AgreementKDFParameters(FipsAlgorithm algorithm, byte[] shared, byte[] iv)
        {
            super(algorithm);

            this.shared = shared;
            this.iv = iv;
        }

        public AgreementKDFParameters withIV(byte[] iv)
        {
            return new AgreementKDFParameters(getAlgorithm(), shared, Arrays.clone(iv));
        }
    }

    /**
     * Factory for operators that derive key material and are associated with key agreement.
     */
    public static final class AgreementOperatorFactory
        extends FipsKDFOperatorFactory<AgreementKDFParameters>
    {
        /**
         * Create an operator factory for creating key agreement KDF generators (X9.63/Concatenation).
         */
        public AgreementOperatorFactory()
        {

        }

        public KDFCalculator<AgreementKDFParameters> createKDFCalculator(final AgreementKDFParameters params)
        {
            if (params.getAlgorithm().getName().startsWith(X963.getAlgorithm().getName()))
            {
                return createX963KDFCalculator(approvedModeOnly, params);
            }
            else
            {
                return createConcatenationKDFCalculator(approvedModeOnly, params);
            }
        }
    }

    /**
     * Factory for operators that derive key material using the X9.63 KDF.
     */
    private static KDFCalculator<AgreementKDFParameters> createX963KDFCalculator(boolean approvedModeOnly, final AgreementKDFParameters params)
    {
        Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

        final DerivationFunction df = new KDF2BytesGenerator(FipsSHS.createDigest(((AgreementKDFPRF)params.getAlgorithm().basicVariation()).algorithm));

        df.init(new KDFParameters(params.shared, params.iv));

        return new MonitoringKDFCalculator<AgreementKDFParameters>(approvedModeOnly, new BaseKDFCalculator<AgreementKDFParameters>()
        {
            public AgreementKDFParameters getParameters()
            {
                return params;
            }

            public void generateBytes(byte[] out, int outOff, int len)
            {
                df.generateBytes(out, outOff, len);
            }
        });
    }

    /**
     * Factory method for operators that derive key material using the SP800-56A Concatenation KDF.
     */
    private static KDFCalculator<AgreementKDFParameters> createConcatenationKDFCalculator(boolean approvedModeOnly, final AgreementKDFParameters params)
    {
        Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

        final DerivationFunction df = new ConcatenationKDFGenerator(FipsSHS.createDigest(((AgreementKDFPRF)params.getAlgorithm().basicVariation()).algorithm));

        df.init(new KDFParameters(params.shared, params.iv));

        return new MonitoringKDFCalculator<AgreementKDFParameters>(approvedModeOnly, new BaseKDFCalculator<AgreementKDFParameters>()
        {
            public AgreementKDFParameters getParameters()
            {
                return params;
            }

            public void generateBytes(byte[] out, int outOff, int len)
            {
                df.generateBytes(out, outOff, len);
            }
        });
    }

    /**
     * An enumeration of the FIPS approved psuedo-random-function (PRF) for KDFs used with IKEv2.
     */
    public enum IKEv2PRF
    {
        SHA1(FipsSHS.Algorithm.SHA1_HMAC),
        SHA224(FipsSHS.Algorithm.SHA224_HMAC),
        SHA256(FipsSHS.Algorithm.SHA256_HMAC),
        SHA384(FipsSHS.Algorithm.SHA384_HMAC),
        SHA512(FipsSHS.Algorithm.SHA512_HMAC);

        private final FipsAlgorithm algorithm;

        IKEv2PRF(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public FipsAlgorithm getAlgorithm()
        {
            return algorithm;
        }
    }

    /**
     * Parameters builder for the IKEv2 key derivation function.
     */
    public static class IKEv2ParametersBuilder
        extends FipsParameters
    {
        private final IKEv2PRF prf;

        IKEv2ParametersBuilder(FipsAlgorithm algorithm, IKEv2PRF prf)
        {
            super(algorithm);
            this.prf = prf;
        }

        public IKEv2ParametersBuilder withPRF(IKEv2PRF prf)
        {
            return new IKEv2ParametersBuilder(getAlgorithm(), prf);
        }

        public IKEv2PRF getPRF()
        {
            return prf;
        }

        public IKEv2Parameters createForPrf(byte[] shared, byte[]... keyPad)
        {
            return new IKEv2Parameters(new FipsAlgorithm(getAlgorithm(), prf), false, Arrays.clone(shared), Arrays.concatenate(keyPad));
        }

        public IKEv2Parameters createForPrfPlus(byte[] shared, byte[]... keyPad)
        {
            return new IKEv2Parameters(new FipsAlgorithm(getAlgorithm(), prf), true, Arrays.clone(shared), Arrays.concatenate(keyPad));
        }
    }

    /**
     * Parameters for the IKVEv2 key derivation function.
     */
    public static class IKEv2Parameters
        extends FipsParameters
    {
        private final boolean isPlus;
        private final byte[] shared;
        private final byte[] keyPad;

        IKEv2Parameters(FipsAlgorithm algorithm, boolean isPlus, byte[] shared, byte[] keyPad)
        {
            super(algorithm);
            this.isPlus = isPlus;
            this.shared = shared;
            this.keyPad = keyPad;
        }
    }

    /**
     * Factory for operators that derive key material using the IKEv2 KDF.
     */
    public static final class IKEv2OperatorFactory
        extends FipsKDFOperatorFactory<IKEv2Parameters>
    {
        /**
         * Create an operator factory for creating IKEv2 KDF generators.
         */
        public IKEv2OperatorFactory()
        {

        }

        public KDFCalculator<IKEv2Parameters> createKDFCalculator(final IKEv2Parameters params)
        {
            Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

            final Mac hMac = FipsSHS.createHMac(((IKEv2PRF)params.getAlgorithm().basicVariation()).algorithm);

            return new MonitoringKDFCalculator<IKEv2Parameters>(approvedModeOnly, new BaseKDFCalculator<IKEv2Parameters>()
            {
                public IKEv2Parameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    prf(hMac, params, out, outOff, len);
                }
            });
        }

        private static void prf(Mac hmac, IKEv2Parameters params, byte[] out, int outOff, int len)
        {
            int size = hmac.getMacSize();
            int iterations = (len + size - 1) / size;
            byte[] buf = new byte[size];


            if (!params.isPlus)
            {
                hmac.init(new KeyParameterImpl(params.shared));
                hmac.update(params.keyPad, 0, params.keyPad.length);
                hmac.doFinal(buf, 0);

                System.arraycopy(buf, 0, out, outOff, buf.length);
            }
            else
            {
                hmac.init(new KeyParameterImpl(params.shared));
                hmac.update(params.keyPad, 0, params.keyPad.length);
                hmac.update((byte)1);

                hmac.doFinal(buf, 0);

                System.arraycopy(buf, 0, out, outOff, Math.min(size, len));

                for (int i = 1; i < iterations; i++)
                {
                    hmac.update(buf, 0, buf.length);
                    hmac.update(params.keyPad, 0, params.keyPad.length);
                    hmac.update((byte)(i + 1));

                    hmac.doFinal(buf, 0);

                    System.arraycopy(buf, 0, out, outOff + (size * i), Math.min(size, out.length - (size * i)));
                }
            }
        }
    }

    /**
     * An enumeration of the FIPS approved psuedo-random-function (PRF) for KDFs used with SRTP.
     */
    public enum SRTPPRF
    {
        AES_CM(FipsAES.CTR.getAlgorithm(), FipsAES.ENGINE_PROVIDER);

        private final FipsAlgorithm algorithm;
        private final EngineProvider<BlockCipher> engineProvider;

        SRTPPRF(FipsAlgorithm algorithm, EngineProvider<BlockCipher> engineProvider)
        {
            this.algorithm = algorithm;
            this.engineProvider = engineProvider;
        }

        public FipsAlgorithm getAlgorithm()
        {
            return algorithm;
        }
    }

    /**
     * Parameters for the SRTP key derivation function.
     */
    public static class SRTPParametersBuilder
        extends FipsParameters
    {
        private final SRTPPRF prf;

        SRTPParametersBuilder(FipsAlgorithm algorithm, SRTPPRF prf)
        {
            super(algorithm);
            this.prf = prf;
        }

        public SRTPParametersBuilder withPRF(SRTPPRF prf)
        {
            return new SRTPParametersBuilder(getAlgorithm(), prf);
        }

        public SRTPParameters using(byte[] kMaster, byte[] masterSalt, int kdr, byte[] index)
        {
            return new SRTPParameters(new FipsAlgorithm(getAlgorithm(), prf), (byte)0, Arrays.clone(kMaster), Arrays.clone(masterSalt), kdr, Arrays.clone(index));
        }

        public SRTPPRF getPRF()
        {
            return prf;
        }
    }

    /**
     * Parameters for the SRTP key derivation function.
     */
    public static class SRTPParameters
        extends FipsParameters
    {
        private final byte label;
        private final byte[] kMaster;
        private final byte[] masterSalt;
        private final int kdr;
        private final byte[] index;
        private final byte[] div;

        SRTPParameters(FipsAlgorithm algorithm, byte label, byte[] kMaster, byte[] masterSalt, int kdr, byte[] index)
        {
            super(algorithm);

            this.label = label;
            this.kMaster = kMaster;
            this.masterSalt = masterSalt;
            this.kdr = kdr;
            this.index = index;
            this.div = new byte[index.length];

            if (kdr != 0)
            {
                byte[] adjusted;
                if (index.length <= 7)
                {
                    byte[] val = new byte[8];

                    System.arraycopy(index, 0, val, val.length - index.length, index.length);

                    long ind = Pack.bigEndianToLong(val, 0) / kdr;

                    adjusted = Pack.longToBigEndian(ind);
                }
                else
                {
                    BigInteger ind = new BigInteger(1, index).divide(BigInteger.valueOf(kdr));

                    adjusted = ind.toByteArray();
                }

                if (adjusted.length < div.length)
                {
                    System.arraycopy(adjusted, 0, div, div.length - adjusted.length, adjusted.length);
                }
                else
                {
                    System.arraycopy(adjusted, adjusted.length - div.length, div, 0, div.length);
                }
            }
        }

        public SRTPParameters withLabel(byte label)
        {
            return new SRTPParameters(this.getAlgorithm(), label, this.kMaster, this.masterSalt, this.kdr, this.index);
        }
    }

    /**
     * Factory for operators that derive key material using the SRTP KDF.
     */
    public static final class SRTPOperatorFactory
        extends FipsKDFOperatorFactory<SRTPParameters>
    {
        /**
         * Create an operator factory for creating SRTP KDF generators.
         */
        public SRTPOperatorFactory()
        {

        }

        public KDFCalculator<SRTPParameters> createKDFCalculator(final SRTPParameters params)
        {
            Utils.approvedModeCheck(approvedModeOnly, params.getAlgorithm());

            final SICBlockCipher prfEngine = new SICBlockCipher(((SRTPPRF)params.getAlgorithm().basicVariation()).engineProvider.createEngine());

            byte[] iv = new byte[prfEngine.getBlockSize()];

            System.arraycopy(params.masterSalt, 0, iv, 0, params.masterSalt.length);

            iv[params.masterSalt.length - (params.div.length + 1)] ^= params.label;
            for (int i = 0; i != params.div.length; i++)
            {
                iv[i + (params.masterSalt.length - params.div.length)] ^= params.div[i];
            }

            prfEngine.init(true, new ParametersWithIV(new KeyParameterImpl(params.kMaster), iv));

            return new MonitoringKDFCalculator<SRTPParameters>(approvedModeOnly, new BaseKDFCalculator<SRTPParameters>()
            {
                public SRTPParameters getParameters()
                {
                    return params;
                }

                public void generateBytes(byte[] out, int outOff, int len)
                {
                    prf(prfEngine, out, outOff, len);
                }
            });
        }

        private static void prf(StreamCipher prfEngine, byte[] out, int outOff, int len)
        {
            for (int i = outOff; i != outOff + len; i++)
            {
                out[i] = 0;
            }

            prfEngine.processBytes(out, outOff, len, out, outOff);
        }
    }

    private interface BaseKDFCalculator<T extends Parameters>
    {
        T getParameters();

        void generateBytes(byte[] out, int outOff, int len);
    }
    
    private static class MonitoringKDFCalculator<T extends Parameters>
        implements KDFCalculator<T>
    {
        private final boolean approvedModeOnly;
        private final BaseKDFCalculator<T> kdf;
        private final FipsAlgorithm algorithm;

        MonitoringKDFCalculator(boolean approvedModeOnly, BaseKDFCalculator<T> kdf)
        {
            this.approvedModeOnly = approvedModeOnly;
            this.kdf = kdf;
            this.algorithm = (FipsAlgorithm)kdf.getParameters().getAlgorithm();
        }

        public T getParameters()
        {
            Utils.approvedModeCheck(approvedModeOnly, algorithm);

            return kdf.getParameters();
        }

        public void generateBytes(byte[] out)
        {
            generateBytes(out, 0, out.length);
        }

        public void generateBytes(byte[] out, int outOff, int len)
        {
            Utils.approvedModeCheck(approvedModeOnly, algorithm);

            kdf.generateBytes(out, outOff, len);
        }
    }

    private static EngineProvider<Digest> md5Provider = new EngineProvider<Digest>()
    {
        public Digest createEngine()
        {
            // FSM_STATE:3.KDF.0, TLS 1.0 KAT, "The module is performing the KAT test for the MD5 digest in TLS 1.0"
            // FSM_TRANS:3.KDF.0, "POWER ON SELF-TEST",	"TLS 1.0 KDF GENERATE VERIFY KAT",	"Invoke MD5 digest in TLS 1.0 KDF Generate/Verify KAT self-test"
            return SelfTestExecutor.validate(FipsKDF.TLS1_0.getAlgorithm(), new MD5Digest(), new Md5KatTest());
            // FSM_TRANS:3.KDF.1, "TLS 1.0 KDF GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"MD5 digest in TLS 1.0 KDF KAT self-test successful completion"

        }
    };

    private static class Md5KatTest
        implements BasicKatTest<Digest>
    {
        private static final byte[] stdShaVector = Strings.toByteArray("abc");
        private static final byte[] kat = Hex.decode("900150983cd24fb0d6963f7d28e17f72");

        public boolean hasTestPassed(Digest digest)
        {
            digest.update(stdShaVector, 0, stdShaVector.length);

            byte[] result = new byte[digest.getDigestSize()];

            digest.doFinal(result, 0);

            return Arrays.areEqual(result, kat);
        }
    }

    private static final class CounterModeProvider
        extends FipsEngineProvider<KDFCounterBytesGenerator>
    {
        private static final byte[] KI = Hex.decode("dff1e50ac0b69dc40f1051d46c2b069c");
        private static final byte[] FIP = new byte[] { 0x01 };
        private static final byte[] FIS = new byte[] { 0x02 };

        private static final byte[] aes_cmac_vec = Hex.decode("53023e21d00cc5046b15");
        private static final byte[] tripleDes_vec = Hex.decode("d4e062f13b0baefa4943");
        private static final byte[] sha1_vec = Hex.decode("76f881b780e4939d485a");
        private static final byte[] sha224_vec = Hex.decode("66db824abdf2b4e85de2");
        private static final byte[] sha256_vec = Hex.decode("3a46d9be7ab8ea092558");
        private static final byte[] sha384_vec = Hex.decode("d209b2f985ff77301fd1");
        private static final byte[] sha512_vec = Hex.decode("0c51da7c89503acc0050");
        private static final byte[] sha512_224_vec = Hex.decode("86e14446abd90b94c828");
        private static final byte[] sha512_256_vec = Hex.decode("26593c9ef9b39d94bafc");

        private final FipsAlgorithm algorithm;

        public CounterModeProvider(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public CounterModeProvider(PRF prf)
        {
            this.algorithm = new FipsAlgorithm(COUNTER_MODE.getAlgorithm(), prf);
        }

        public KDFCounterBytesGenerator createEngine()
        {
            final PRF prf = (PRF)algorithm.basicVariation();
            FipsEngineProvider<Mac>  macProvider = createPRF(prf);

            return SelfTestExecutor.validate(algorithm, new KDFCounterBytesGenerator(macProvider.createEngine()), new VariantKatTest<KDFCounterBytesGenerator>()
            {
                public void evaluate(KDFCounterBytesGenerator kdfGenerator)
                {
                    kdfGenerator.init(new KDFCounterParameters(KI, FIP, FIS, 8));

                    byte[] out = new byte[10];

                    kdfGenerator.generateBytes(out, 0, out.length);

                    if (!Arrays.areEqual(expectedOutput(prf), out))
                    {
                        fail("failed self test on generation: " + Hex.toHexString(out));
                    }
                }
            });
        }

        private static byte[] expectedOutput(PRF prf)
        {
            switch (prf)
            {
            case AES_CMAC:
                return aes_cmac_vec;
            case TRIPLEDES_CMAC:
                return tripleDes_vec;
            case SHA1_HMAC:
                return sha1_vec;
            case SHA224_HMAC:
                return sha224_vec;
            case SHA256_HMAC:
                return sha256_vec;
            case SHA384_HMAC:
                return sha384_vec;
            case SHA512_HMAC:
                return sha512_vec;
            case SHA512_224_HMAC:
                return sha512_224_vec;
            case SHA512_256_HMAC:
                return sha512_256_vec;
            default:
                throw new SelfTestExecutor.TestFailedException("unknown PRF");
            }
        }
    }

    private static final class FeedbackModeProvider
        extends FipsEngineProvider<KDFFeedbackBytesGenerator>
    {
        private static final byte[] KI = Hex.decode("dff1e50ac0b69dc40f1051d46c2b069c");
        private static final byte[] IV = new byte[]{0x01};
        private static final byte[] FID = new byte[]{0x02};

        private static final byte[] aes_cmac_vec = Hex.decode("af7eb5b9a3eb72a1a0cb");
        private static final byte[] tripleDes_vec = Hex.decode("cf65681ac0d3c4f65ce0");
        private static final byte[] sha1_vec = Hex.decode("bfe9d9a6cd8b7befe0fb");
        private static final byte[] sha224_vec = Hex.decode("71d5790138202ab1edc9");
        private static final byte[] sha256_vec = Hex.decode("650d3f9da0f4a8bcf602");
        private static final byte[] sha384_vec = Hex.decode("2a9375ae10e75a9a5ba2");
        private static final byte[] sha512_vec = Hex.decode("e0f3f35c27358f3d0dda");
        private static final byte[] sha512_224_vec = Hex.decode("5fd1372077522505be4a");
        private static final byte[] sha512_256_vec = Hex.decode("ae930bec79b81ee15c67");

        private final FipsAlgorithm algorithm;

        public FeedbackModeProvider(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public FeedbackModeProvider(PRF prf)
        {
            this.algorithm = new FipsAlgorithm(FEEDBACK_MODE.getAlgorithm(), prf);
        }

        public KDFFeedbackBytesGenerator createEngine()
        {
            final PRF prf = (PRF)algorithm.basicVariation();
            FipsEngineProvider<Mac> macProvider = createPRF(prf);

            return SelfTestExecutor.validate(algorithm, new KDFFeedbackBytesGenerator(macProvider.createEngine()), new VariantKatTest<KDFFeedbackBytesGenerator>()
            {
                public void evaluate(KDFFeedbackBytesGenerator kdfGenerator)
                {
                    kdfGenerator.init(KDFFeedbackParameters.createWithCounter(KDFFeedbackParameters.AFTER_FIXED, KI, IV, FID, 8));

                    byte[] out = new byte[10];

                    kdfGenerator.generateBytes(out, 0, out.length);

                    if (!Arrays.areEqual(expectedOutput(prf), out))
                    {
                        fail("failed self test on generation: " + Hex.toHexString(out));
                    }
                }
            });
        }

        private static byte[] expectedOutput(PRF prf)
        {
            switch (prf)
            {
            case AES_CMAC:
                return aes_cmac_vec;
            case TRIPLEDES_CMAC:
                return tripleDes_vec;
            case SHA1_HMAC:
                return sha1_vec;
            case SHA224_HMAC:
                return sha224_vec;
            case SHA256_HMAC:
                return sha256_vec;
            case SHA384_HMAC:
                return sha384_vec;
            case SHA512_HMAC:
                return sha512_vec;
            case SHA512_224_HMAC:
                return sha512_224_vec;
            case SHA512_256_HMAC:
                return sha512_256_vec;
            default:
                throw new SelfTestExecutor.TestFailedException("unknown PRF");
            }
        }
    }

    private static final class DoublePipelineModeProvider
        extends FipsEngineProvider<KDFDoublePipelineIterationBytesGenerator>
    {
        private static final byte[] KI = Hex.decode("dff1e50ac0b69dc40f1051d46c2b069c");
        private static final byte[] FID = new byte[]{0x02};

        private static final byte[] aes_cmac_vec = Hex.decode("ace76ed103e31681ed03");
        private static final byte[] tripleDes_vec = Hex.decode("41d79be29b5c34ffa40d");
        private static final byte[] sha1_vec = Hex.decode("e5e5666cb2a73b8ce638");
        private static final byte[] sha224_vec = Hex.decode("c4c12b540e51d106abd8");
        private static final byte[] sha256_vec = Hex.decode("b6c232a28b4b450210ee");
        private static final byte[] sha384_vec = Hex.decode("48268b8bf87297a5ce8f");
        private static final byte[] sha512_vec = Hex.decode("52d86063e22a84188285");
        private static final byte[] sha512_224_vec = Hex.decode("d1f521fbc7e736685709");
        private static final byte[] sha512_256_vec = Hex.decode("dca0e9d25e22ca54c0ca");

        private final FipsAlgorithm algorithm;

        public DoublePipelineModeProvider(FipsAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public DoublePipelineModeProvider(PRF prf)
        {
            this.algorithm = new FipsAlgorithm(DOUBLE_PIPELINE_ITERATION_MODE.getAlgorithm(), prf);
        }

        public KDFDoublePipelineIterationBytesGenerator createEngine()
        {
            final PRF prf = (PRF)algorithm.basicVariation();
            FipsEngineProvider<Mac> macProvider = createPRF(prf);

            return SelfTestExecutor.validate(algorithm, new KDFDoublePipelineIterationBytesGenerator(macProvider.createEngine()), new VariantKatTest<KDFDoublePipelineIterationBytesGenerator>()
            {
                public void evaluate(KDFDoublePipelineIterationBytesGenerator kdfGenerator)
                {
                    kdfGenerator.init(KDFDoublePipelineIterationParameters.createWithCounter(KDFFeedbackParameters.BEFORE_ITER, KI, FID, 8));

                    byte[] out = new byte[10];

                    kdfGenerator.generateBytes(out, 0, out.length);

                    if (!Arrays.areEqual(expectedOutput(prf), out))
                    {
                        fail("failed self test on generation: " + Hex.toHexString(out));
                    }
                }
            });
        }

        private static byte[] expectedOutput(PRF prf)
        {
            switch (prf)
            {
            case AES_CMAC:
                return aes_cmac_vec;
            case TRIPLEDES_CMAC:
                return tripleDes_vec;
            case SHA1_HMAC:
                return sha1_vec;
            case SHA224_HMAC:
                return sha224_vec;
            case SHA256_HMAC:
                return sha256_vec;
            case SHA384_HMAC:
                return sha384_vec;
            case SHA512_HMAC:
                return sha512_vec;
            case SHA512_224_HMAC:
                return sha512_224_vec;
            case SHA512_256_HMAC:
                return sha512_256_vec;
            default:
                throw new SelfTestExecutor.TestFailedException("unknown PRF");
            }
        }
    }
}
