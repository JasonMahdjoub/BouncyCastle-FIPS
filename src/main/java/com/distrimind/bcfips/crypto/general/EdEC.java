package com.distrimind.bcfips.crypto.general;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.Agreement;
import com.distrimind.bcfips.crypto.AgreementFactory;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.InvalidSignatureException;
import com.distrimind.bcfips.crypto.OutputSigner;
import com.distrimind.bcfips.crypto.OutputVerifier;
import com.distrimind.bcfips.crypto.PlainInputProcessingException;
import com.distrimind.bcfips.crypto.UpdateOutputStream;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricEdDSAPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricKeyPair;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricXDHPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricXDHPublicKey;
import com.distrimind.bcfips.crypto.fips.FipsSHS;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;
import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPair;
import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bcfips.crypto.internal.CipherParameters;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.KeyGenerationParameters;
import com.distrimind.bcfips.crypto.internal.RawAgreement;
import com.distrimind.bcfips.crypto.internal.Signer;
import com.distrimind.bcfips.crypto.internal.Xof;
import com.distrimind.bcfips.crypto.internal.io.SignerOutputStream;
import com.distrimind.bcfips.crypto.internal.params.AsymmetricKeyParameter;
import com.distrimind.bcfips.crypto.internal.test.ConsistencyTest;
import com.distrimind.bcfips.math.ec.rfc8032.Ed25519;
import com.distrimind.bcfips.math.ec.rfc8032.Ed448;
import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.util.encoders.Hex;

/**
 * Source class for implementations of Edwards Elliptic Curve based algorithms.
 */
public final class EdEC
{

    public static final byte[] ZERO_CONTEXT = new byte[0];

    private EdEC()
    {

    }

    public static final class Algorithm
    {
        private Algorithm()
        {

        }

        public static final GeneralAlgorithm Ed448 = new GeneralAlgorithm("Ed448", Variations.Ed448);
        public static final GeneralAlgorithm Ed25519 = new GeneralAlgorithm("Ed25519", Variations.Ed25519);

        public static final GeneralAlgorithm X448 = new GeneralAlgorithm("X448", Variations.X448);
        public static final GeneralAlgorithm X25519 = new GeneralAlgorithm("X25519", Variations.X25519);
    }

    public static final Parameters EdDSA = new Parameters(null);
    public static final Parameters Ed448 = new Parameters(Algorithm.Ed448);
    public static final Parameters Ed25519 = new Parameters(Algorithm.Ed25519);

    public static final Parameters X448 = new Parameters(Algorithm.X448);
    public static final Parameters X25519 = new Parameters(Algorithm.X25519);

    private enum Variations
    {
        Ed448,
        Ed25519,
        X448,
        X25519
    }

    public static final int X448_PUBLIC_KEY_SIZE = X448PublicKeyParameters.KEY_SIZE;
    public static final int X25519_PUBLIC_KEY_SIZE = X25519PublicKeyParameters.KEY_SIZE;
    public static final int Ed448_PUBLIC_KEY_SIZE = Ed448PublicKeyParameters.KEY_SIZE;
    public static final int Ed25519_PUBLIC_KEY_SIZE = Ed25519PublicKeyParameters.KEY_SIZE;

    public static final int X448_PRIVATE_KEY_SIZE = X448PrivateKeyParameters.KEY_SIZE;
    public static final int X25519_PRIVATE_KEY_SIZE = X25519PrivateKeyParameters.KEY_SIZE;
    public static final int Ed448_PRIVATE_KEY_SIZE = Ed448PrivateKeyParameters.KEY_SIZE;
    public static final int Ed25519_PRIVATE_KEY_SIZE = Ed25519PrivateKeyParameters.KEY_SIZE;

    /**
     * Edwards Curve key pair generation parameters.
     */
    public static class Parameters
        extends GeneralParameters<GeneralAlgorithm>
    {
        /**
         * Base constructor.
         *
         * @param algorithm the EdEC domain parameters algorithm.
         */
        Parameters(GeneralAlgorithm algorithm)
        {
            super(algorithm);
        }
    }
    
    /**
     * Edwards Curve DSA key pair generator.
     */
    public static final class EdDSAKeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator
    {
        private final Variations variation;
        private final AsymmetricCipherKeyPairGenerator kpGen;

        public EdDSAKeyPairGenerator(Parameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            switch ((Variations)keyGenParameters.getAlgorithm().basicVariation())
            {
            case Ed448:
                this.variation = Variations.Ed448;
                this.kpGen = new Ed448KeyPairGenerator();
                break;
            case Ed25519:
                this.variation = Variations.Ed25519;
                this.kpGen = new Ed25519KeyPairGenerator();
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            kpGen.init(new KeyGenerationParameters(random, 0));    // strength ignored
        }

        @Override
        protected AsymmetricKeyPair doGenerateKeyPair()
        {
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            validateSigningKeyPair(kp);
            
            switch (variation)
            {
            case Ed448:
                return new AsymmetricKeyPair(
                    new AsymmetricEdDSAPublicKey(getParameters().getAlgorithm(), ((Ed448PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricEdDSAPrivateKey(getParameters().getAlgorithm(), ((Ed448PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((Ed448PublicKeyParameters)kp.getPublic()).getEncoded()));
            case Ed25519:
                return new AsymmetricKeyPair(
                    new AsymmetricEdDSAPublicKey(getParameters().getAlgorithm(), ((Ed25519PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricEdDSAPrivateKey(getParameters().getAlgorithm(), ((Ed25519PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((Ed25519PublicKeyParameters)kp.getPublic()).getEncoded()));
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }
        }
    }

    /**
     * Edwards Curve Diffie-Hellman key pair generator.
     */
    public static final class XDHKeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator
    {
        private final Variations variation;
        private final AsymmetricCipherKeyPairGenerator kpGen;

        public XDHKeyPairGenerator(Parameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            switch ((Variations)keyGenParameters.getAlgorithm().basicVariation())
            {
            case X448:
                this.variation = Variations.X448;
                this.kpGen = new X448KeyPairGenerator();
                break;
            case X25519:
                this.variation = Variations.X25519;
                this.kpGen = new X25519KeyPairGenerator();
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            kpGen.init(new KeyGenerationParameters(random, 0));    // strength ignored
        }

        @Override
        protected AsymmetricKeyPair doGenerateKeyPair()
        {
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            validateAgreementKeyPair(kp);
 
            switch (variation)
            {
            case X448:
                return new AsymmetricKeyPair(
                    new AsymmetricXDHPublicKey(getParameters().getAlgorithm(), ((X448PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricXDHPrivateKey(getParameters().getAlgorithm(), ((X448PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((X448PublicKeyParameters)kp.getPublic()).getEncoded()));
            case X25519:
                return new AsymmetricKeyPair(
                    new AsymmetricXDHPublicKey(getParameters().getAlgorithm(), ((X25519PublicKeyParameters)kp.getPublic()).getEncoded()),
                    new AsymmetricXDHPrivateKey(getParameters().getAlgorithm(), ((X25519PrivateKeyParameters)kp.getPrivate()).getEncoded(), ((X25519PublicKeyParameters)kp.getPublic()).getEncoded()));
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }
        }
    }

    /**
     * Operator factory for creating Edwards Curve DSA based signing and verification operators.
     */
    public static final class EdDSAOperatorFactory
        extends GuardedSignatureOperatorFactory<Parameters>
    {
        public EdDSAOperatorFactory()
        {
        }

        @Override
        protected OutputSigner<Parameters> doCreateSigner(AsymmetricPrivateKey key, final Parameters parameters)
        {
            final Signer signer;
            final GeneralAlgorithm algorithm = (parameters.getAlgorithm() != null) ? parameters.getAlgorithm() : (GeneralAlgorithm)key.getAlgorithm();

            switch ((Variations)algorithm.basicVariation())
            {
            case Ed448:
                signer = new Ed448Signer(ZERO_CONTEXT);

                signer.init(true, getLwKey((AsymmetricEdDSAPrivateKey)key));
                break;
            case Ed25519:
                signer = new Ed25519Signer();

                signer.init(true, getLwKey((AsymmetricEdDSAPrivateKey)key));
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            return new OutputSigner<Parameters>()
            {

                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getSigningStream()
                {
                    return new SignerOutputStream(algorithm.getName(), signer);
                }

                public byte[] getSignature()
                    throws PlainInputProcessingException
                {
                    try
                    {
                        return signer.generateSignature();
                    }
                    catch (Exception e)
                    {
                        throw new PlainInputProcessingException("Unable to create signature: " + e.getMessage(), e);
                    }
                }

                public int getSignature(byte[] output, int off)
                    throws PlainInputProcessingException
                {
                    byte[] sig = getSignature();

                    System.arraycopy(sig, 0, output, off, sig.length);

                    return sig.length;
                }
            };
        }

        @Override
        protected OutputVerifier<Parameters> doCreateVerifier(AsymmetricPublicKey key, final Parameters parameters)
        {
            final Signer signer;
            final GeneralAlgorithm algorithm = (parameters.getAlgorithm() != null) ? parameters.getAlgorithm() : (GeneralAlgorithm)key.getAlgorithm();

            switch ((Variations)algorithm.basicVariation())
            {
            case Ed448:
                signer = new Ed448Signer(new byte[0]);

                signer.init(false, getLwKey((AsymmetricEdDSAPublicKey)key));
                break;
            case Ed25519:
                signer = new Ed25519Signer();

                signer.init(false, getLwKey((AsymmetricEdDSAPublicKey)key));
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            return new OutputVerifier<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public UpdateOutputStream getVerifyingStream()
                {
                    return new SignerOutputStream(algorithm.getName(), signer);
                }

                public boolean isVerified(byte[] signature)
                    throws InvalidSignatureException
                {
                    return signer.verifySignature(signature);
                }
            };
        }
    }

    /**
     * Factory for Agreement operators based on Edwards Curve Diffie-Hellman.
     */
    public static final class XDHAgreementFactory
        implements AgreementFactory<Parameters>
    {
        public XDHAgreementFactory()
        {
            FipsStatus.isReady();
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
            }
        }

        public Agreement<Parameters> createAgreement(AsymmetricPrivateKey key, final Parameters parameters)
        {
            final RawAgreement agreement;

            switch ((Variations)parameters.getAlgorithm().basicVariation())
            {
            case X448:
                agreement = new X448Agreement();

                agreement.init(getLwKey((AsymmetricXDHPrivateKey)key));
                break;
            case X25519:
                agreement = new X25519Agreement();

                agreement.init(getLwKey((AsymmetricXDHPrivateKey)key));
                break;
            default:
                throw new IllegalArgumentException("unknown algorithm");
            }

            return new Agreement<Parameters>()
            {
                public Parameters getParameters()
                {
                    return parameters;
                }

                public byte[] calculate(AsymmetricPublicKey key)
                {
                    AsymmetricKeyParameter lwKey = getLwKey((AsymmetricXDHPublicKey)key);
                    byte[] sharedValue;

                    if (lwKey instanceof X448PublicKeyParameters)
                    {
                         sharedValue = new byte[X448PrivateKeyParameters.SECRET_SIZE];
                    }
                    else
                    {
                        sharedValue = new byte[X25519PrivateKeyParameters.SECRET_SIZE];
                    }

                    agreement.calculateAgreement(lwKey, sharedValue, 0);

                    return sharedValue;
                }
            };
        }
    }

    public static byte[] computePublicData(com.distrimind.bcfips.crypto.Algorithm algorithm, byte[] secret)
    {
        byte[] publicKey;

        if (algorithm.equals(EdEC.Algorithm.Ed448))
        {
            final Ed448 ed448 = new Ed448()
            {
                @Override
                protected Xof createXof()
                {
                    return (Xof)Register.createDigest(FipsSHS.Algorithm.SHAKE256);
                }
            };

            publicKey = new byte[Ed448_PUBLIC_KEY_SIZE];
            ed448.generatePublicKey(secret, 0, publicKey, 0);
        }
        else if (algorithm.equals(Algorithm.Ed25519))
        {
            final Ed25519 ed25519 = new Ed25519()
            {
                @Override
                protected Digest createDigest()
                {
                    return Register.createDigest(FipsSHS.Algorithm.SHA512);
                }
            };

            publicKey = new byte[Ed25519_PUBLIC_KEY_SIZE];
            ed25519.generatePublicKey(secret, 0, publicKey, 0);
        }
        else if (algorithm.equals(EdEC.Algorithm.X448))
        {
            publicKey = new byte[X448_PUBLIC_KEY_SIZE];
            com.distrimind.bcfips.math.ec.rfc7748.X448.scalarMultBase(secret, 0, publicKey, 0);
        }
        else
        {
            publicKey = new byte[X25519_PUBLIC_KEY_SIZE];
            com.distrimind.bcfips.math.ec.rfc7748.X25519.scalarMultBase(secret, 0, publicKey, 0);
        }

        return publicKey;
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricEdDSAPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (privKey.getAlgorithm().equals(Algorithm.Ed448))
                {
                    return new Ed448PrivateKeyParameters(privKey.getSecret(), 0);
                }
                else
                {
                    return new Ed25519PrivateKeyParameters(privKey.getSecret(), 0);
                }
            }
        });
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricEdDSAPublicKey pubKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (pubKey.getAlgorithm().equals(Algorithm.Ed448))
                {
                    return new Ed448PublicKeyParameters(pubKey.getPublicData(), 0);
                }
                else
                {
                    return new Ed25519PublicKeyParameters(pubKey.getPublicData(), 0);
                }
            }
        });
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricXDHPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (privKey.getAlgorithm().equals(Algorithm.X448))
                {
                    return new X448PrivateKeyParameters(privKey.getSecret(), 0);
                }
                else
                {
                    return new X25519PrivateKeyParameters(privKey.getSecret(), 0);
                }
            }
        });
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricXDHPublicKey pubKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                if (pubKey.getAlgorithm().equals(Algorithm.X448))
                {
                    return new X448PublicKeyParameters(pubKey.getPublicData(), 0);
                }
                else
                {
                    return new X25519PublicKeyParameters(pubKey.getPublicData(), 0);
                }
            }
        });
    }

    private static final byte[] x448Secret = Hex.decode("683ea9b2857ff88fff5160bede45edb3b64f5d76c2c3ef6ef0479caa65c6ec2bcddaf76e3c3c61dcc557a09771b7593cf6240c2328b4054f");
    private static final byte[] x448Public = Hex.decode("daafe9ae6984c3ab2fea0498990ee3c1690aac801e508a735e037436dcd16435c5fa93b5186e668247c4c1e9560a3d2e53a1136ca714978b");

    private static final byte[] x25519Secret = Hex.decode("4a434deaa453db96d893c92d4193d5ccb0002e74121548f936c2a313b9fd3a49");
    private static final byte[] x25519Public = Hex.decode("722143ed71a72fb2f6ecb3a2549d09d0e9db308b79450c38cd2d406ef8723167");

    private static void validateAgreementKeyPair(AsymmetricCipherKeyPair kp)
    {
        if (kp.getPublic() instanceof X448PublicKeyParameters)
        {
            SelfTestExecutor.validate(Algorithm.X448, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkayAgreeing(new X448Agreement(), kp, new X448PrivateKeyParameters(x448Secret, 0), new X448PublicKeyParameters(x448Public, 0));
                }
            });
        }
        else
        {
            SelfTestExecutor.validate(Algorithm.X25519, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkayAgreeing(new X25519Agreement(), kp, new X25519PrivateKeyParameters(x25519Secret, 0), new X25519PublicKeyParameters(x25519Public, 0));
                }
            });
        }
    }

    private static boolean isOkayAgreeing(RawAgreement agreement, AsymmetricCipherKeyPair kp,
                                          CipherParameters testPriv, CipherParameters testPub)
    {
        try
        {
            byte[] rv1 = new byte[agreement.getAgreementSize()];
            byte[] rv2 = new byte[agreement.getAgreementSize()];

            agreement.init(kp.getPrivate());

            agreement.calculateAgreement(testPub, rv1, 0);

            agreement.init(testPriv);

            agreement.calculateAgreement(kp.getPublic(), rv2, 0);

            return Arrays.areEqual(rv1, rv2);
        }
        catch (Exception e)
        {
            return false;
        }
    }

    private static final byte[] data = Hex.decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

    private static void validateSigningKeyPair(AsymmetricCipherKeyPair kp)
    {
        if (kp.getPublic() instanceof Ed448PublicKeyParameters)
        {
            SelfTestExecutor.validate(Algorithm.Ed448, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkaySigning(new Ed448Signer(ZERO_CONTEXT), kp);
                }
            });
        }
        else
        {
            SelfTestExecutor.validate(Algorithm.Ed25519, kp, new ConsistencyTest<AsymmetricCipherKeyPair>()
            {
                public boolean hasTestPassed(AsymmetricCipherKeyPair kp)
                {
                    return isOkaySigning(new Ed25519Signer(), kp);
                }
            });
        }
    }

    private static boolean isOkaySigning(Signer signer, AsymmetricCipherKeyPair kp)
    {
        try
        {
            signer.init(true, kp.getPrivate());

            signer.update(data, 0, data.length);

            byte[] rv = signer.generateSignature();

            signer.init(false, kp.getPublic());

            signer.update(data, 0, data.length);

            return signer.verifySignature(rv);
        }
        catch (Exception e)
        {
            return false;
        }
    }
}
