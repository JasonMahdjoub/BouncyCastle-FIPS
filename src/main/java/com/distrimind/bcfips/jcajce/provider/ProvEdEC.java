package com.distrimind.bcfips.jcajce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;
import com.distrimind.bcfips.asn1.edec.EdECObjectIdentifiers;
import com.distrimind.bcfips.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bcfips.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricKeyPairGenerator;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricEdDSAPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricKeyPair;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricXDHPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricXDHPublicKey;
import com.distrimind.bcfips.crypto.general.EdEC;
import com.distrimind.bcfips.jcajce.spec.EdDSAParameterSpec;
import com.distrimind.bcfips.jcajce.spec.XDHParameterSpec;

class ProvEdEC
    extends AsymmetricAlgorithmProvider
{
    private static final Map<String, String> generalEdDSAAttributes = new HashMap<String, String>();
    private static final Map<String, String> generalXDHAttributes = new HashMap<String, String>();

    static
    {
        generalEdDSAAttributes.put("SupportedKeyClasses", "com.distrimind.bcfips.interfaces.EdDSAKey");
        generalEdDSAAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
        generalXDHAttributes.put("SupportedKeyClasses", "com.distrimind.bcfips.interfaces.XDHKey");
        generalXDHAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private static final String PREFIX = "com.distrimind.bcfips.jcajce.provider.asymmetric" + ".edec.";

    private static final byte x448_type = 0x6f;
    private static final byte x25519_type = 0x6e;
    private static final byte Ed448_type = 0x71;
    private static final byte Ed25519_type = 0x70;

    private static final PublicKeyConverter<AsymmetricEdDSAPublicKey> edPublicKeyConverter = new PublicKeyConverter<AsymmetricEdDSAPublicKey>()
    {
        public AsymmetricEdDSAPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvEdDSAPublicKey)
            {
                return ((ProvEdDSAPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricEdDSAPublicKey(Utils.getKeyEncoding(key));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify EdDSA public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricEdDSAPrivateKey> edPrivateKeyConverter = new PrivateKeyConverter<AsymmetricEdDSAPrivateKey>()
    {
        public AsymmetricEdDSAPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvEdDSAPrivateKey)
            {
                return ((ProvEdDSAPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricEdDSAPrivateKey(PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify EdDSA private key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PublicKeyConverter<AsymmetricXDHPublicKey> xPublicKeyConverter = new PublicKeyConverter<AsymmetricXDHPublicKey>()
    {
        public AsymmetricXDHPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvXDHPublicKey)
            {
                return ((ProvXDHPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricXDHPublicKey(Utils.getKeyEncoding(key));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify XDH public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricXDHPrivateKey> xPrivateKeyConverter = new PrivateKeyConverter<AsymmetricXDHPrivateKey>()
    {
        public AsymmetricXDHPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof ProvXDHPrivateKey)
            {
                return ((ProvXDHPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricXDHPrivateKey(PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify XDH private key: " + e.getMessage(), e);
                }
            }
        }
    };

    static class KeyFactorySpi
        extends BaseKeyFactory
    {
        String algorithm;
        private final boolean isXdh;
        private final int specificBase;

        public KeyFactorySpi(
            String algorithm,
            boolean isXdh,
            int specificBase)
        {
            this.algorithm = algorithm;
            this.isXdh = isXdh;
            this.specificBase = specificBase;
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                if (isXdh)
                {
                    Algorithm alg = key.getAlgorithm().equals("X448") ? EdEC.Algorithm.X448 : EdEC.Algorithm.X25519;
                    return new ProvXDHPublicKey(xPublicKeyConverter.convertKey(alg, (PublicKey)key));
                }
                else
                {
                    Algorithm alg = key.getAlgorithm().equals("Ed448") ? EdEC.Algorithm.Ed448 : EdEC.Algorithm.Ed25519;
                    return new ProvEdDSAPublicKey(edPublicKeyConverter.convertKey(alg, (PublicKey)key));
                }
            }
            else if (key instanceof PrivateKey)
            {
                if (isXdh)
                {
                    Algorithm alg = key.getAlgorithm().equals("X448") ? EdEC.Algorithm.X448 : EdEC.Algorithm.X25519;
                    return new ProvXDHPrivateKey(xPrivateKeyConverter.convertKey(alg, (PrivateKey)key));
                }
                else
                {
                    Algorithm alg = key.getAlgorithm().equals("Ed448") ? EdEC.Algorithm.Ed448 : EdEC.Algorithm.Ed25519;
                    return new ProvEdDSAPrivateKey(edPrivateKeyConverter.convertKey(alg, (PrivateKey)key));
                }
            }
            else if (key != null)
            {
                throw new InvalidKeyException("Key type unrecognized: " + key.getClass().getName());
            }
            throw new InvalidKeyException("Key is null");
        }

        protected KeySpec engineGetKeySpec(
            Key key,
            Class spec)
            throws InvalidKeySpecException
        {
            if (spec == null)
            {
                throw new InvalidKeySpecException("null spec is invalid");
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof X509EncodedKeySpec)
            {
                byte[] enc = ((X509EncodedKeySpec)keySpec).getEncoded();
                // optimise if we can
                if (specificBase == 0 || specificBase == enc[8])
                {
                    switch (enc[8])
                    {
                    case x448_type:
                        return new ProvXDHPublicKey(enc);
                    case x25519_type:
                        return new ProvXDHPublicKey(enc);
                    case Ed448_type:
                        return new ProvEdDSAPublicKey(enc);
                    case Ed25519_type:
                        return new ProvEdDSAPublicKey(enc);
                    default:
                        return super.engineGeneratePublic(keySpec);
                    }
                }
            }

            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

            if (isXdh)
            {
                if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(EdECObjectIdentifiers.id_X448))
                {
                    return new ProvXDHPrivateKey(keyInfo);
                }
                if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
                {
                    return new ProvXDHPrivateKey(keyInfo);
                }
            }
            else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return new ProvEdDSAPrivateKey(keyInfo);
                }
                if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
                {
                    return new ProvEdDSAPrivateKey(keyInfo);
                }
            }

            throw new IOException("algorithm identifier " + algOid + " in key not recognized");
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

            if (isXdh)
            {
                if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(EdECObjectIdentifiers.id_X448))
                {
                    return new ProvXDHPublicKey(keyInfo.getEncoded());
                }
                if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
                {
                    return new ProvXDHPublicKey(keyInfo.getEncoded());
                }
            }
            else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
                {
                    return new ProvEdDSAPublicKey(keyInfo.getEncoded());
                }
                if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
                {
                    return new ProvEdDSAPublicKey(keyInfo.getEncoded());
                }
            }

            throw new IOException("algorithm identifier " + algOid + " in key not recognized");
        }

        static class XDH
            extends KeyFactorySpi
        {
            public XDH()
            {
                super("XDH", true, 0);
            }
        }

        static class X448
            extends KeyFactorySpi
        {
            public X448()
            {
                super("X448", true, x448_type);
            }
        }

        static class X25519
            extends KeyFactorySpi
        {
            public X25519()
            {
                super("X25519", true, x25519_type);
            }
        }

        static class EdDSA
            extends KeyFactorySpi
        {
            public EdDSA()
            {
                super("EdDSA", false, 0);
            }
        }

        static class Ed448
            extends KeyFactorySpi
        {
            public Ed448()
            {
                super("Ed448", false, Ed448_type);
            }
        }

        static class Ed25519
            extends KeyFactorySpi
        {
            public Ed25519()
            {
                super("Ed25519", false, Ed25519_type);
            }
        }
    }


    static class KeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider provider;
        private final boolean isXDH;

        private EdEC.Parameters params;
        private AsymmetricKeyPairGenerator engine;
        private SecureRandom random;
        private boolean initialised = false;

        public KeyPairGeneratorSpi(BouncyCastleFipsProvider provider, boolean isXDH, EdEC.Parameters params)
        {
            super(params != null ? params.getAlgorithm().getName() : (isXDH ? "XDH" : "EdDSA"));
            this.params = params;
            this.provider = provider;
            this.isXDH = isXDH;
        }

        public void initialize(
            int strength)
        {
            initialize(strength, provider.getDefaultSecureRandom());
        }

        public void initialize(int strength, SecureRandom secureRandom)
        {
            this.random = secureRandom;

            switch (strength)
            {
            case 255:
            case 256:
                if (isXDH)
                {
                    if (params != null && params != EdEC.X25519)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }
                    this.params = EdEC.X25519;
                }
                else
                {
                    if (params != null && params != EdEC.Ed25519)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }
                    this.params = EdEC.Ed25519;
                }
                break;
            case 448:
                if (isXDH)
                {
                    if (params != null && params != EdEC.X448)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }
                    this.params = EdEC.X448;
                }
                else
                {
                    if (params != null && params != EdEC.Ed448)
                    {
                        throw new InvalidParameterException("key size not configurable");
                    }                       
                    this.params = EdEC.Ed448;
                }
                break;
            default:
                throw new InvalidParameterException("unknown key size.");
            }
        }

        public void initialize(
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            initialize(params, provider.getDefaultSecureRandom());
        }

        public void initialize(
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (params instanceof ECGenParameterSpec)
            {
                this.params = getParams(((ECGenParameterSpec)params).getName());
            }
            else if (!isXDH && params instanceof EdDSAParameterSpec)
            {
                this.params = getParams(((EdDSAParameterSpec)params).getCurveName());
            }
            else if (isXDH && params instanceof XDHParameterSpec)
            {
                this.params = getParams(((XDHParameterSpec)params).getCurveName());
            }
            else
            {
                if (params == null)
                {
                    throw new InvalidAlgorithmParameterException("parameterSpec cannot be null");
                }
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }

            this.random = random;
        }

        private EdEC.Parameters getParams(String name)
            throws InvalidAlgorithmParameterException
        {
            if (isXDH)
            {
                if (name.equalsIgnoreCase(XDHParameterSpec.X448) || name.equals(EdECObjectIdentifiers.id_X448.getId()))
                {
                    return EdEC.X448;
                }
                if (name.equalsIgnoreCase(XDHParameterSpec.X25519) || name.equals(EdECObjectIdentifiers.id_X25519.getId()))
                {
                    return EdEC.X25519;
                }
                throw new InvalidAlgorithmParameterException("unknown curve name: " + name);
            }
            else
            {
                if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed448) || name.equals(EdECObjectIdentifiers.id_Ed448.getId()))
                {
                    return EdEC.Ed448;
                }
                if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed25519) || name.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
                {
                    return EdEC.Ed25519;
                }
                throw new InvalidAlgorithmParameterException("unknown curve name: " + name);
            }
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                if (params == null)
                {
                    throw new IllegalStateException("generator not correctly initialized");
                }

                if (random == null)
                {
                    random = provider.getDefaultSecureRandom();
                }

                if (isXDH)
                {
                    engine = new EdEC.XDHKeyPairGenerator(params, random);
                }
                else
                {
                    engine = new EdEC.EdDSAKeyPairGenerator(params, random);
                }
                initialised = true;
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();

            if (isXDH)
            {
                AsymmetricXDHPublicKey pub = (AsymmetricXDHPublicKey)pair.getPublicKey();
                AsymmetricXDHPrivateKey priv = (AsymmetricXDHPrivateKey)pair.getPrivateKey();

                return new KeyPair(new ProvXDHPublicKey(pub), new ProvXDHPrivateKey(priv));
            }
            else
            {
                AsymmetricEdDSAPublicKey pub = (AsymmetricEdDSAPublicKey)pair.getPublicKey();
                AsymmetricEdDSAPrivateKey priv = (AsymmetricEdDSAPrivateKey)pair.getPrivateKey();

                return new KeyPair(new ProvEdDSAPublicKey(pub), new ProvEdDSAPrivateKey(priv));
            }
        }
    }

    static class XDHParametersCreator
        implements ParametersCreator
    {
        private final EdEC.Parameters params;

        XDHParametersCreator(EdEC.Parameters params)
        {
            this.params = params;
        }

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (spec != null)
            {
                throw new InvalidAlgorithmParameterException("unable to take parameter specs");
            }
            return params;
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyFactory.XDH", PREFIX + "KeyFactorySpi$XDH", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.XDH();
            }
        }));
        provider.addAlgorithmImplementation("KeyFactory.X448", PREFIX + "KeyFactorySpi$X448", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.X448();
            }
        }));
        provider.addAlgorithmImplementation("KeyFactory.X25519", PREFIX + "KeyFactorySpi$X25519", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.X25519();
            }
        }));

        provider.addAlgorithmImplementation("KeyFactory.EDDSA", PREFIX + "KeyFactorySpi$EdDH", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.EdDSA();
            }
        }));
        provider.addAlgorithmImplementation("KeyFactory.ED448", PREFIX + "KeyFactorySpi$Ed448", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.Ed448();
            }
        }));
        provider.addAlgorithmImplementation("KeyFactory.ED25519", PREFIX + "KeyFactorySpi$Ed25519", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi.Ed25519();
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.EDDSA", PREFIX + "KeyPairGeneratorSpi$EdDSA", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, false, null);
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.ED448", PREFIX + "KeyPairGeneratorSpi$Ed448", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, false, EdEC.Ed448);
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.ED25519", PREFIX + "KeyPairGeneratorSpi$Ed25519", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, false, EdEC.Ed25519);
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.XDH", PREFIX + "KeyPairGeneratorSpi$XDH", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, true,null);
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.X448", PREFIX + "KeyPairGeneratorSpi$X448", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, true, EdEC.X448);
            }
        }));

        provider.addAlgorithmImplementation("KeyPairGenerator.X25519", PREFIX + "KeyPairGeneratorSpi$X25519", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider, true, EdEC.X25519);
            }
        }));

        provider.addAlgorithmImplementation("Signature.EDDSA", PREFIX + "Signature$EDDSA", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new EdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, EdEC.EdDSA);
            }
        }));

        provider.addAlgorithmImplementation("Signature.ED448", PREFIX + "Signature$Ed448", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new EdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, EdEC.Ed448);
            }
        }));
        provider.addAlias("Signature", "ED448", EdECObjectIdentifiers.id_Ed448);

        provider.addAlgorithmImplementation("Signature.ED25519", PREFIX + "Signature$Ed25519", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new EdEC.EdDSAOperatorFactory(), edPublicKeyConverter, edPrivateKeyConverter, EdEC.Ed25519);
            }
        }));
        provider.addAlias("Signature", "ED25519", EdECObjectIdentifiers.id_Ed25519);
        
        addKeyAgreementAlgorithm(provider, "XDH", PREFIX + "KeyAgreementSpi$XDH", generalXDHAttributes, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(new EdEC.XDHAgreementFactory(), xPublicKeyConverter, xPrivateKeyConverter, new XDHParametersCreator(EdEC.X448));
            }
        }));

        addKeyAgreementAlgorithm(provider, "X448", PREFIX + "KeyAgreementSpi$X448", generalXDHAttributes, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(new EdEC.XDHAgreementFactory(), xPublicKeyConverter, xPrivateKeyConverter, new XDHParametersCreator(EdEC.X448));
            }
        }));
        provider.addAlias("KeyAgreement", "X448", EdECObjectIdentifiers.id_X448);

        addKeyAgreementAlgorithm(provider, "X25519", PREFIX + "KeyAgreementSpi$X25519", generalXDHAttributes, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(new EdEC.XDHAgreementFactory(), xPublicKeyConverter, xPrivateKeyConverter, new XDHParametersCreator(EdEC.X25519));
            }
        }));
        provider.addAlias("KeyAgreement", "X25519", EdECObjectIdentifiers.id_X25519);

        registerOid(provider, EdECObjectIdentifiers.id_X448, "X448", new KeyFactorySpi.X448());
        registerOid(provider, EdECObjectIdentifiers.id_X25519, "X25519", new KeyFactorySpi.X25519());
        registerOid(provider, EdECObjectIdentifiers.id_Ed448, "ED448", new KeyFactorySpi.Ed448());
        registerOid(provider, EdECObjectIdentifiers.id_Ed25519, "ED25519", new KeyFactorySpi.Ed25519());
    }
}
