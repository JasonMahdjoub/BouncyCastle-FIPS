package com.distrimind.bcfips.jcajce.provider;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;
import com.distrimind.bcfips.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bcfips.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.EntropySource;
import com.distrimind.bcfips.crypto.EntropySourceProvider;
import com.distrimind.bcfips.crypto.SecureRandomProvider;
import com.distrimind.bcfips.crypto.fips.FipsDRBG;
import com.distrimind.bcfips.crypto.fips.FipsSecureRandom;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.util.BasicEntropySourceProvider;
import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.util.Pack;
import com.distrimind.bcfips.util.Properties;
import com.distrimind.bcfips.util.Strings;

/**
 * The BC FIPS provider.
 * <p>
 * If no SecureRandom has been specified using CryptoServicesRegistrar.setSecureRandom() the provider class will generate a
 * FIPS compliant DRBG based on SHA-512. It is also possible to configure the DRBG by passing a string as a constructor
 * argument to the provider via code, or the java.security configuration file.
 * </p>
 * <p>
 * At the moment the configuration string is limited to setting the DRBG.The configuration string must always start
 * with "C:" and finish with "ENABLE{ALL};". The command for setting the actual DRBG type is DEFRND so a configuration
 * string requesting the use of a SHA1 DRBG would look like:
 * <pre>
 *         C:DEFRND[SHA1];ENABLE{ALL};
 *     </pre>
 * Possible values for the DRBG type are "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512(224)", "SHA512(256)",
 * "HMACrovRandSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA512(224)", "HMACSHA512(256)", "CTRAES128",
 * "CTRAES192", CTRAES256", and "CTRDESEDE".
 * </p>
 * <p>
 * The default DRBG is configured to be prediction resistant. In situations where the amount of entropy is constrained
 * the default DRBG can be configured to use an entropy pool based on a SHA-512 SP 800-90A DRBG. To configure this use:
 * <pre>
 *         C:HYBRID;ENABLE{ALL};
 *     </pre>
 * or include the string "HYBRID;" in the previous command string setting the DRBG. After initial seeding the entropy pool will
 * start a reseeding thread which it will begin polling once 20 samples have been taken since the last seeding and will do a reseed
 * as soon as new entropy bytes are returned.
 * </p>
 * <p>
 * <b>Note</b>: if the provider is created by an "approved mode" thread, only FIPS approved algorithms will be available from it.
 * </p>
 */
public final class BouncyCastleFipsProvider
    extends Provider
{
    private static final String info = "BouncyCastle Security Provider (FIPS edition) v1.0.2.5";

    public static final String PROVIDER_NAME = "BCFIPS";

    private static final Map<String, FipsDRBG.Base> drbgTable = new HashMap<String, FipsDRBG.Base>();
    private static final Map<String, Integer> drbgStrengthTable = new HashMap<String, Integer>();

    static
    {
        drbgTable.put("SHA1", FipsDRBG.SHA1);
        drbgTable.put("SHA224", FipsDRBG.SHA224);
        drbgTable.put("SHA256", FipsDRBG.SHA256);
        drbgTable.put("SHA384", FipsDRBG.SHA384);
        drbgTable.put("SHA512", FipsDRBG.SHA512);
        drbgTable.put("SHA512(224)", FipsDRBG.SHA512_224);
        drbgTable.put("SHA512(256)", FipsDRBG.SHA512_256);

        drbgTable.put("HMACSHA1", FipsDRBG.SHA1_HMAC);
        drbgTable.put("HMACSHA224", FipsDRBG.SHA224_HMAC);
        drbgTable.put("HMACSHA256", FipsDRBG.SHA256_HMAC);
        drbgTable.put("HMACSHA384", FipsDRBG.SHA384_HMAC);
        drbgTable.put("HMACSHA512", FipsDRBG.SHA512_HMAC);
        drbgTable.put("HMACSHA512(224)", FipsDRBG.SHA512_224_HMAC);
        drbgTable.put("HMACSHA512(256)", FipsDRBG.SHA512_256_HMAC);

        drbgTable.put("CTRAES128", FipsDRBG.CTR_AES_128);
        drbgTable.put("CTRAES192", FipsDRBG.CTR_AES_192);
        drbgTable.put("CTRAES256", FipsDRBG.CTR_AES_256);
        drbgTable.put("CTRDESEDE", FipsDRBG.CTR_Triple_DES_168);

        drbgStrengthTable.put("SHA1", 128);
        drbgStrengthTable.put("SHA224", 192);
        drbgStrengthTable.put("SHA256", 256);
        drbgStrengthTable.put("SHA384", 256);
        drbgStrengthTable.put("SHA512", 256);
        drbgStrengthTable.put("SHA512(224)", 192);
        drbgStrengthTable.put("SHA512(256)", 256);

        drbgStrengthTable.put("HMACSHA1", 128);
        drbgStrengthTable.put("HMACSHA224", 192);
        drbgStrengthTable.put("HMACSHA256", 256);
        drbgStrengthTable.put("HMACSHA384", 256);
        drbgStrengthTable.put("HMACSHA512", 256);
        drbgStrengthTable.put("HMACSHA512(224)", 192);
        drbgStrengthTable.put("HMACSHA512(256)", 256);

        drbgStrengthTable.put("CTRAES128", 128);
        drbgStrengthTable.put("CTRAES192", 192);
        drbgStrengthTable.put("CTRAES256", 256);
        drbgStrengthTable.put("CTRDESEDE", 112);
    }

    private volatile SecureRandom entropySource;

    private Thread entropyThread = null;
    private EntropyDaemon entropyDaemon = null;

    private FipsDRBG.Base providerDefaultRandomBuilder = FipsDRBG.SHA512;
    private int providerDefaultSecurityStrength = 256;
    private boolean providerDefaultPredictionResistance = true;
    private boolean useThreadLocal = false;
    private int providerRandomPoolSize = 16;

    private boolean hybridSource = false;
    private int providerDefaultRandomSecurityStrength = providerDefaultSecurityStrength;
    private final SecureRandomProvider providerDefaultSecureRandomProvider;

    private Map<String, BcService> serviceMap = new HashMap<String, BcService>();
    private Map<String, EngineCreator> creatorMap = new HashMap<String, EngineCreator>();

    private final Map<ASN1ObjectIdentifier, AsymmetricKeyInfoConverter> keyInfoConverters = new HashMap<ASN1ObjectIdentifier, AsymmetricKeyInfoConverter>();

    /**
     * Base constructor - build a provider with the default configuration.
     */
    public BouncyCastleFipsProvider()
    {
        this(null);
    }

    /**
     * Constructor accepting a configuration string.
     *
     * @param config the config string.
     */
    public BouncyCastleFipsProvider(String config)
    {
        this(config, null);
    }

    /**
     * Constructor accepting a config string and a user defined source of entropy to be used for the providers locally
     * configured DRBG.
     *
     * @param config        the config string.
     * @param entropySource a SecureRandom which can act as an entropy source.
     */
    public BouncyCastleFipsProvider(String config, SecureRandom entropySource)
    {
        super(PROVIDER_NAME, 1.000205, info);

        // TODO: add support for file parsing, selective disable.

        if (config != null)
        {
            if (config.startsWith("C:") || config.startsWith("c:"))
            {
                processConfigString(Strings.toUpperCase(config));
            }
            else
            {
                throw new IllegalArgumentException("Unrecognized config string passed to " + PROVIDER_NAME + " provider.");
            }
        }

        this.entropySource = entropySource;   // used by getEntropySourceProvider() if set.

        if (useThreadLocal)
        {
            providerDefaultSecureRandomProvider = new ThreadLocalSecureRandomProvider();
        }
        else
        {
            providerDefaultSecureRandomProvider = new PooledSecureRandomProvider();
        }

        new ProvRandom().configure(this);

        new ProvSHS.SHA1().configure(this);
        new ProvSHS.SHA224().configure(this);
        new ProvSHS.SHA256().configure(this);
        new ProvSHS.SHA384().configure(this);
        new ProvSHS.SHA512().configure(this);
        new ProvSHS.SHA3_224().configure(this);
        new ProvSHS.SHA3_256().configure(this);
        new ProvSHS.SHA3_384().configure(this);
        new ProvSHS.SHA3_512().configure(this);
        if (!isDisabled("MD5"))
        {
            new ProvSecureHash.MD5().configure(this);  // TLS exception
        }

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvSecureHash.GOST3411().configure(this);

            new ProvSecureHash.RIPEMD128().configure(this);
            new ProvSecureHash.RIPEMD160().configure(this);
            new ProvSecureHash.RIPEMD256().configure(this);
            new ProvSecureHash.RIPEMD320().configure(this);
            new ProvSecureHash.Tiger().configure(this);
            new ProvSecureHash.Whirlpool().configure(this);
        }

        new ProvDH().configure(this);
        new ProvDSA().configure(this);

        if (!Properties.isOverrideSet("com.distrimind.bcfips.ec.disable"))
        {
            new ProvEC().configure(this);
        }

        new ProvRSA().configure(this);

        new ProvPBEPBKDF2().configure(this);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvPBEPBKDF1().configure(this);
            new ProvOpenSSLPBKDF().configure(this);
            new ProvPKCS12().configure(this);
        }

        new ProvAES().configure(this);
        new ProvDESede().configure(this);

        new ProvX509().configure(this);
        new ProvBCFKS().configure(this);
        new ProvFipsKS().configure(this);

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            new ProvEdEC().configure(this);
            new ProvDSTU4145().configure(this);
            new ProvElgamal().configure(this);
            new ProvGOST3410().configure(this);
            new ProvECGOST3410().configure(this);

            new ProvBlowfish().configure(this);
            new ProvCAST5().configure(this);
            new ProvRC2().configure(this);
            new ProvGOST28147().configure(this);
            new ProvSEED().configure(this);
            new ProvCamellia().configure(this);
            new ProvChaCha20().configure(this);
            new ProvDES().configure(this);
            new ProvIDEA().configure(this);
            new ProvSerpent().configure(this);
            new ProvSHACAL2().configure(this);
            new ProvTwofish().configure(this);
            new ProvARC4().configure(this);
            new ProvSipHash().configure(this);
            new ProvPoly1305().configure(this);
        }



        if (!Properties.isOverrideSet("com.distrimind.bcfips.pkix.disable_certpath"))
        {
            new ProvPKIX().configure(this);
        }

        if (Properties.isOverrideSet("com.distrimind.bcfips.jca.enable_jks"))
        {
            new ProvJKS().configure(this);
        }
    }

    // for Java 11
    public Provider configure(String configArg)
    {
        return new BouncyCastleFipsProvider(configArg);
    }

    private void processConfigString(String config)
    {
        String[] commands = config.substring(2).split(";");
        boolean enableAllFound = false;

        for (String command : commands)
        {
            if (command.startsWith("DEFRND"))
            {
                String rndConfig = extractString('[', ']', command).trim();

                String rnd;
                while (rndConfig != null)
                {
                    int commaPos = rndConfig.indexOf(",");
                    if (commaPos > 0)
                    {
                        rnd = rndConfig.substring(0, commaPos).trim();
                        rndConfig = rndConfig.substring(commaPos + 1);
                    }
                    else
                    {
                        rnd = rndConfig;
                        rndConfig = null;
                    }

                    if (rnd.equals("TRUE") || rnd.equals("FALSE"))
                    {
                        providerDefaultPredictionResistance = Boolean.valueOf(rnd);
                    }
                    else if (rnd.equals("LOCAL"))
                    {
                        useThreadLocal = true;
                    }
                    else if (rnd.startsWith("POOL="))
                    {
                        providerRandomPoolSize = Integer.parseInt(rnd.substring(5));
                    }
                    else
                    {
                        // digest name
                        providerDefaultRandomBuilder = drbgTable.get(rnd);
                        if (drbgStrengthTable.containsKey(rnd))
                        {
                            providerDefaultSecurityStrength = drbgStrengthTable.get(rnd);
                        }
                        if (providerDefaultRandomBuilder == null)
                        {
                            throw new IllegalArgumentException("Unknown DEFRND - " + rnd + " - found in config string.");
                        }
                    }
                }
            }
            else if (command.startsWith("HYBRID"))
            {
                hybridSource = true;
                entropyDaemon = new EntropyDaemon();
                entropyThread = new Thread(entropyDaemon, "BC FIPS Entropy Daemon");
                entropyThread.setDaemon(true);
                entropyThread.start();
            }
            else if (command.startsWith("ENABLE"))
            {
                if ("ENABLE{ALL}".equals(command))
                {
                    enableAllFound = true;
                }
            }
        }

        if (!enableAllFound)
        {
            throw new IllegalArgumentException("No ENABLE command found in config string.");
        }
    }

    private String extractString(char startC, char endC, String command)
    {
        int start = command.indexOf(startC);
        int end = command.indexOf(endC);

        if (start < 0 || end < 0)
        {
            throw new IllegalArgumentException("Unable to parse config: ('" + startC + "', '" + endC + "') missing.");
        }

        return command.substring(start + 1, end);
    }

    int getProviderDefaultSecurityStrength()
    {
        return providerDefaultSecurityStrength;
    }

    FipsDRBG.Base getProviderDefaultRandomBuilder()
    {
        return providerDefaultRandomBuilder;
    }

    public SecureRandom getDefaultSecureRandom()
    {
        SecureRandom defRandom = CryptoServicesRegistrar.getSecureRandomIfSet(providerDefaultSecureRandomProvider);
 
        synchronized (this)
        {
            // we only allow this value to go down as we want to avoid people getting the wrong idea
            // about a provider produced random they might have.
            if (defRandom instanceof FipsSecureRandom)
            {
                int securityStrength = ((FipsSecureRandom)defRandom).getSecurityStrength();

                if (securityStrength < providerDefaultRandomSecurityStrength)
                {
                    providerDefaultRandomSecurityStrength = securityStrength;
                }
            }
            else
            {
                providerDefaultRandomSecurityStrength = -1;     // unknown
            }
        }

        return defRandom;
    }

    EntropySourceProvider getEntropySourceProvider()
    {
        // this has to be a lazy evaluation
        return AccessController.doPrivileged(new PrivilegedAction<EntropySourceProvider>()
        {
            public EntropySourceProvider run()
            {
                if (hybridSource)
                {
                    return new EntropySourceProvider()
                    {
                        @Override
                        public EntropySource get(int bitsRequired)
                        {
                            return new HybridEntropySource(entropyDaemon, bitsRequired);
                        }
                    };
                }

                if (entropySource != null)
                {
                    return new BasicEntropySourceProvider(entropySource, true);
                }

                return new BasicEntropySourceProvider(getCoreSecureRandom(), true);
            }
        });
    }

    private static SecureRandom getCoreSecureRandom()
    {
        boolean hasGetInstanceStrong = AccessController.doPrivileged(new PrivilegedAction<Boolean>()
        {
            public Boolean run()
            {
                try
                {
                    Class def = SecureRandom.class;

                    return def.getMethod("getInstanceStrong") != null;
                }
                catch (Exception e)
                {
                    return false;
                }
            }
        });

        if (hasGetInstanceStrong)
        {
            return AccessController.doPrivileged(new PrivilegedAction<SecureRandom>()
            {
                public SecureRandom run()
                {
                    try
                    {
                        return (SecureRandom)SecureRandom.class.getMethod("getInstanceStrong").invoke(null);
                    }
                    catch (Exception e)
                    {
                        return new CoreSecureRandom();  // fallback
                    }
                }
            });
        }
        else
        {
            return new CoreSecureRandom();
        }
    }

    /**
     * Return the default random security strength.
     *
     * @return the security strength for the default SecureRandom the provider uses.
     */
    public int getDefaultRandomSecurityStrength()
    {
        synchronized (this)
        {
            return providerDefaultRandomSecurityStrength;
        }
    }

    void addAttribute(String key, String attributeName, String attributeValue)
    {
        String attributeKey = key + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttribute(String type, ASN1ObjectIdentifier oid, String attributeName, String attributeValue)
    {
        String attributeKey = type + "." + oid + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttributes(String key, Map<String, String> attributes)
    {
        for (Map.Entry<String, String> attrEntry : attributes.entrySet())
        {
            addAttribute(key, attrEntry.getKey(), attrEntry.getValue());
        }
    }

    void addAttributes(String type, ASN1ObjectIdentifier oid, Map<String, String> attributes)
    {
        for (Map.Entry<String, String> attrEntry : attributes.entrySet())
        {
            addAttribute(type, oid, attrEntry.getKey(), attrEntry.getValue());
        }
    }

    void addAlgorithmImplementation(String key, String className, Map<String, String> attributes, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");
        addAttributes(key, attributes);

        put(key, className);
        creatorMap.put(className, creator);
    }

    void addAlgorithmImplementation(String key, String className, EngineCreator creator)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        addAttribute(key, "ImplementedIn", "Software");

        put(key, className);
        creatorMap.put(className, creator);
    }

    void addAlgorithmImplementation(String type, ASN1ObjectIdentifier oid, String className, EngineCreator creator)
    {
        String key1 = type + "." + oid;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttribute(type, oid, "ImplementedIn", "Software");

        put(key1, className);
        creatorMap.put(className, creator);

        addAlias(type, oid.getId(), "OID." + oid.getId());
    }

    void addAlgorithmImplementation(String type, ASN1ObjectIdentifier oid, String className, Map<String, String> attributes, EngineCreator creator)
    {
        String key1 = type + "." + oid;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttributes(type, oid, attributes);
        addAttribute(type, oid, "ImplementedIn", "Software");

        put(key1, className);
        creatorMap.put(className, creator);

        addAlias(type, oid.getId(), "OID." + oid.getId());
    }

    void addAlias(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    void addAlias(String type, String name, String... aliases)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (String alias : aliases)
        {
            doPut("Alg.Alias." + type + "." + alias, name);
        }
    }

    void addAlias(String type, String name, ASN1ObjectIdentifier... oids)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (ASN1ObjectIdentifier oid : oids)
        {
            doPut("Alg.Alias." + type + "." + oid, name);
            doPut("Alg.Alias." + type + ".OID." + oid, name);
        }
    }

    private void doPut(String key, String name)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, name);
    }

    public synchronized final Service getService(String type, String algorithm)
    {
        String upperCaseAlgName = Strings.toUpperCase(algorithm);

        BcService service = serviceMap.get(type + "." + upperCaseAlgName);

        if (service == null)
        {
            String aliasString = "Alg.Alias." + type + ".";
            String realName = (String)this.get(aliasString + upperCaseAlgName);

            if (realName == null)
            {
                realName = upperCaseAlgName;
            }

            String className = (String)this.get(type + "." + realName);

            if (className == null)
            {
                return null;
            }

            String attributeKeyStart = type + "." + realName + " ";

            List<String> aliases = new ArrayList<String>();
            Map<String, String> attributes = new HashMap<String, String>();

            for (Map.Entry<Object, Object> entry : this.entrySet())
            {
                String sKey = (String)entry.getKey();
                if (sKey.startsWith(aliasString))
                {
                    if (entry.getValue().equals(algorithm))
                    {
                        aliases.add(sKey.substring(aliasString.length()));
                    }
                }
                if (sKey.startsWith(attributeKeyStart))
                {
                    attributes.put(sKey.substring(attributeKeyStart.length()), (String)entry.getValue());
                }
            }

            service = new BcService(this, type, upperCaseAlgName, className, aliases, getAttributeMap(attributes), creatorMap.get(className));

            serviceMap.put(type + "." + upperCaseAlgName, service);
        }

        return service;
    }

    public synchronized final Set<Service> getServices()
    {
        Set<Service> serviceSet = super.getServices();
        Set<Service> bcServiceSet = new LinkedHashSet<Service>();

        for (Service service : serviceSet)
        {
            bcServiceSet.add(getService(service.getType(), service.getAlgorithm()));
        }

        return bcServiceSet;
    }

    void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
    {
        keyInfoConverters.put(oid, keyInfoConverter);
    }

    private boolean isDisabled(String algName)
    {
        String disabled = Properties.getPropertyValue("com.distrimind.bcfips.disabledAlgorithms");

        return disabled != null && (disabled.indexOf(algName) >= 0);
    }

    private byte[] generatePersonalizationString(int rngIndex)
    {
        return Arrays.concatenate(Pack.intToBigEndian(rngIndex), Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private final Map<Map<String, String>, Map<String, String>> attributeMaps = new HashMap<Map<String, String>, Map<String, String>>();

    private Map<String, String> getAttributeMap(Map<String, String> attributeMap)
    {
        Map<String, String> attrMap = attributeMaps.get(attributeMap);
        if (attrMap != null)
        {
            return attrMap;
        }

        attributeMaps.put(attributeMap, attributeMap);

        return attributeMap;
    }

    private static boolean classExists(String className)
    {
        try
        {
            Class def = ClassUtil.lookup(className);

            return def != null;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        AsymmetricKeyInfoConverter converter = keyInfoConverters.get(publicKeyInfo.getAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePublic(publicKeyInfo);
    }

    PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
        throws IOException
    {
        AsymmetricKeyInfoConverter converter = keyInfoConverters.get(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePrivate(privateKeyInfo);
    }

    private static class BcService
        extends Service
    {
        private final EngineCreator creator;

        /**
         * Construct a new service.
         *
         * @param provider   the provider that offers this service
         * @param type       the type of this service
         * @param algorithm  the algorithm name
         * @param className  the name of the class implementing this service
         * @param aliases    List of aliases or null if algorithm has no aliases
         * @param attributes Map of attributes or null if this implementation
         *                   has no attributes
         * @throws NullPointerException if provider, type, algorithm, or
         *                              className is null
         */
        public BcService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes, EngineCreator creator)
        {
            super(provider, type, algorithm, className, aliases, attributes);
            this.creator = creator;
        }

        public Object newInstance(Object constructorParameter)
            throws NoSuchAlgorithmException
        {
            try
            {
                FipsStatus.isReady();

                Object instance = creator.createInstance(constructorParameter);

                if (instance == null)
                {
                    throw new NoSuchAlgorithmException("No such algorithm in FIPS approved mode: " + getAlgorithm());
                }

                return instance;
            }
            catch (NoSuchAlgorithmException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new NoSuchAlgorithmException("Unable to invoke creator for " + getAlgorithm() + ": " + e.getMessage(), e);
            }
        }
    }

    private static class CoreSecureRandom
        extends SecureRandom
    {
        CoreSecureRandom()
        {
            super();
        }

    }

    private static class EntropyDaemon
        implements Runnable
    {
        private final LinkedList<Runnable> tasks = new LinkedList<Runnable>();

        void addTask(Runnable task)
        {
            synchronized (tasks)
            {
                tasks.add(task);
            }
        }

        @Override
        public void run()
        {
            while (!Thread.currentThread().isInterrupted())
            {
                Runnable task;
                synchronized (tasks)
                {
                    task = tasks.poll();
                }

                if (task != null)
                {
                    try
                    {
                        task.run();
                    }
                    catch (Throwable e)
                    {
                        // ignore
                    }
                }
                else
                {
                    try
                    {
                        Thread.sleep(5000);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
    }

    private static class HybridEntropySource
        implements EntropySource
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);

        private final FipsSecureRandom drbg;
        private final SignallingEntropySource entropySource;
        private final int bytesRequired;

        HybridEntropySource(final EntropyDaemon entropyDaemon, final int bitsRequired)
        {
            SecureRandom baseRandom = getCoreSecureRandom();

            bytesRequired = (bitsRequired + 7) / 8;
            // remember for the seed generator we need the correct security strength for SHA-512
            entropySource = new SignallingEntropySource(entropyDaemon, seedAvailable, baseRandom, 256);
            drbg = FipsDRBG.SHA512.fromEntropySource(new EntropySourceProvider()
                {
                    public EntropySource get(final int bitsRequired)
                    {
                        return entropySource;
                    }
                })
                .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
                .build(baseRandom.generateSeed(32), false, null);     // 32 byte nonce
        }

        @Override
        public boolean isPredictionResistant()
        {
            return true;
        }

        @Override
        public byte[] getEntropy()
        {
            byte[] entropy = new byte[bytesRequired];

            // after 20 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 20)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed();
                }
                else
                {
                    entropySource.schedule();
                }
            }

            drbg.nextBytes(entropy);

            return entropy;
        }

        @Override
        public int entropySize()
        {
            return bytesRequired * 8;
        }

        private class SignallingEntropySource
            implements EntropySource
        {
            private final EntropyDaemon entropyDaemon;
            private final AtomicBoolean seedAvailable;
            private final SecureRandom baseRandom;
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            SignallingEntropySource(EntropyDaemon entropyDaemon, AtomicBoolean seedAvailable, SecureRandom baseRandom, int bitsRequired)
            {
                this.entropyDaemon = entropyDaemon;
                this.seedAvailable = seedAvailable;
                this.baseRandom = baseRandom;
                this.byteLength = (bitsRequired + 7) / 8;
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = baseRandom.generateSeed(byteLength);
                }
                else
                {
                    scheduled.set(false);
                }

                schedule();

                return seed;
            }

            void schedule()
            {
                if (!scheduled.getAndSet(true))
                {
                    entropyDaemon.addTask(new EntropyGatherer(byteLength, baseRandom, seedAvailable, entropy));
                }
            }

            public int entropySize()
            {
                return byteLength * 8;
            }
        }

        private class EntropyGatherer
            implements Runnable
        {
            private final int numBytes;
            private final SecureRandom baseRandom;
            private final AtomicBoolean seedAvailable;
            private final AtomicReference<byte[]> entropy;

            EntropyGatherer(int numBytes, SecureRandom baseRandom, AtomicBoolean seedAvailable, AtomicReference<byte[]> entropy)
            {
                this.numBytes = numBytes;
                this.baseRandom = baseRandom;
                this.seedAvailable = seedAvailable;
                this.entropy = entropy;
            }

            private void sleep(long ms)
            {
                try
                {
                    Thread.sleep(ms);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                }
            }

            public void run()
            {
                long ms;
                String pause = Properties.getPropertyValue("com.distrimind.bcfips.drbg.gather_pause_secs");

                if (pause != null)
                {
                    try
                    {
                        ms = Long.parseLong(pause) * 1000;
                    }
                    catch (Exception e)
                    {
                        ms = 5000;
                    }
                }
                else
                {
                    ms = 5000;
                }

                byte[] seed = new byte[numBytes];
                for (int i = 0; i < numBytes / 8; i++)
                {
                    // we need to be mindful that we may not be the only thread/process looking for entropy
                    sleep(ms);
                    byte[] rn = baseRandom.generateSeed(8);
                    System.arraycopy(rn, 0, seed, i * 8, rn.length);
                }

                int extra = numBytes - ((numBytes / 8) * 8);
                if (extra != 0)
                {
                    sleep(ms);
                    byte[] rn = baseRandom.generateSeed(extra);
                    System.arraycopy(rn, 0, seed, seed.length - rn.length, rn.length);
                }

                entropy.set(seed);
                seedAvailable.set(true);
            }
        }
    }

    private class PooledSecureRandomProvider
        implements SecureRandomProvider
    {
        private final AtomicReference<SecureRandom>[] providerDefaultRandom = new AtomicReference[providerRandomPoolSize];
        private final AtomicInteger providerDefaultRandomCount = new AtomicInteger(0);

        PooledSecureRandomProvider()
        {
            for (int i = 0; i != providerDefaultRandom.length; i++)
            {
                providerDefaultRandom[i] = new AtomicReference<SecureRandom>();
            }
        }

        public SecureRandom get()
        {
            // See SP 800-90A R1 8.6.7 for setting of Nonce - at least 1/2 security strength bits
            int rngIndex = providerDefaultRandomCount.getAndSet((providerDefaultRandomCount.get() + 1) % providerDefaultRandom.length);
            if (providerDefaultRandom[rngIndex].get() == null)
            {
                synchronized (providerDefaultRandom)
                {
                    if (providerDefaultRandom[rngIndex].get() == null)
                    {
                        EntropySourceProvider entropySourceProvider = getEntropySourceProvider();

                        EntropySource seedSource = entropySourceProvider.get((providerDefaultSecurityStrength / 2) + 1);

                        // we set providerDefault here as we end up recursing due to personalization string
                        providerDefaultRandom[rngIndex].compareAndSet(null, providerDefaultRandomBuilder
                            .fromEntropySource(entropySourceProvider)
                            .setPersonalizationString(generatePersonalizationString(rngIndex))
                            .build(seedSource.getEntropy(), providerDefaultPredictionResistance, Strings.toByteArray("Bouncy Castle FIPS Provider")));
                    }
                }
            }

            return providerDefaultRandom[rngIndex].get();
        }
    }

    private class ThreadLocalSecureRandomProvider
        implements SecureRandomProvider
    {
        final ThreadLocal<FipsSecureRandom> defaultRandoms = new ThreadLocal<FipsSecureRandom>();

        public SecureRandom get ()
        {
            // See SP 800-90A R1 8.6.7 for setting of Nonce - at least 1/2 security strength bits
            if (defaultRandoms.get() == null)
            {
                EntropySourceProvider entropySourceProvider = getEntropySourceProvider();
                EntropySource seedSource = entropySourceProvider.get((providerDefaultSecurityStrength / 2) + 1);

                // we set providerDefault here as we end up recursing due to personalization string
                defaultRandoms.set(providerDefaultRandomBuilder
                    .fromEntropySource(entropySourceProvider)
                    .setPersonalizationString(generatePersonalizationString((int)Thread.currentThread().getId()))
                    .build(seedSource.getEntropy(), providerDefaultPredictionResistance, Strings.toByteArray("Bouncy Castle FIPS Provider")));
            }

            return defaultRandoms.get();
        }
    }
}
