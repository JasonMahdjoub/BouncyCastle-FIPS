package com.distrimind.bcfips.jcajce.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;
import com.distrimind.bcfips.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.distrimind.bcfips.asn1.gnu.GNUObjectIdentifiers;
import com.distrimind.bcfips.asn1.kisa.KISAObjectIdentifiers;
import com.distrimind.bcfips.asn1.misc.MiscObjectIdentifiers;
import com.distrimind.bcfips.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bcfips.asn1.ntt.NTTObjectIdentifiers;
import com.distrimind.bcfips.asn1.oiw.OIWObjectIdentifiers;
import com.distrimind.bcfips.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bcfips.crypto.Agreement;
import com.distrimind.bcfips.crypto.AgreementFactory;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.IllegalKeyException;
import com.distrimind.bcfips.crypto.KDFCalculator;
import com.distrimind.bcfips.crypto.KDFOperatorFactory;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricDHKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricDHPublicKey;
import com.distrimind.bcfips.crypto.fips.FipsDH;
import com.distrimind.bcfips.crypto.fips.FipsKDF;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;
import com.distrimind.bcfips.jcajce.AgreedKeyWithMacKey;
import com.distrimind.bcfips.jcajce.spec.DHUParameterSpec;
import com.distrimind.bcfips.jcajce.spec.MQVParameterSpec;
import com.distrimind.bcfips.jcajce.spec.UserKeyingMaterialSpec;
import com.distrimind.bcfips.util.Arrays;
import com.distrimind.bcfips.util.Strings;

/**
 * Diffie-Hellman key agreement using elliptic curve keys, ala IEEE P1363
 * both the simple one, and the simple one with cofactors are supported.
 *
 * Also, MQV key agreement per SEC-1
 */
class BaseAgreement
    extends KeyAgreementSpi
{

    private static final Map<String, ASN1ObjectIdentifier> defaultOids = new HashMap<String, ASN1ObjectIdentifier>();
    private static final Map<String, String> nameTable = new HashMap<String, String>();
    private static final KeyIvSizeProvider keySizeProvider = new KeyIvSizeProvider();

    static
    {
        defaultOids.put("DESEDE", PKCSObjectIdentifiers.des_EDE3_CBC);
        defaultOids.put("AES", NISTObjectIdentifiers.id_aes256_CBC);
        defaultOids.put("CAMELLIA", NTTObjectIdentifiers.id_camellia256_cbc);
        defaultOids.put("SEED", KISAObjectIdentifiers.id_seedCBC);
        defaultOids.put("DES", OIWObjectIdentifiers.desCBC);

        nameTable.put(MiscObjectIdentifiers.cast5CBC.getId(), "CAST5");
        nameTable.put(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.getId(), "IDEA");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB.getId(), "Blowfish");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC.getId(), "Blowfish");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CFB.getId(), "Blowfish");
        nameTable.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_OFB.getId(), "Blowfish");
        nameTable.put(OIWObjectIdentifiers.desECB.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desCBC.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desCFB.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desOFB.getId(), "DES");
        nameTable.put(OIWObjectIdentifiers.desEDE.getId(), "DESede");
        nameTable.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), "DESede");
        nameTable.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), "DESede");
        nameTable.put(PKCSObjectIdentifiers.id_alg_CMSRC2wrap.getId(), "RC2");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA1.getId(), "HmacSHA1");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA224.getId(), "HmacSHA224");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA256.getId(), "HmacSHA256");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA384.getId(), "HmacSHA384");
        nameTable.put(PKCSObjectIdentifiers.id_hmacWithSHA512.getId(), "HmacSHA512");
        nameTable.put(NTTObjectIdentifiers.id_camellia128_cbc.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia192_cbc.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia256_cbc.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia128_wrap.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia192_wrap.getId(), "Camellia");
        nameTable.put(NTTObjectIdentifiers.id_camellia256_wrap.getId(), "Camellia");
        nameTable.put(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId(), "SEED");
        nameTable.put(KISAObjectIdentifiers.id_seedCBC.getId(), "SEED");
        nameTable.put(KISAObjectIdentifiers.id_seedMAC.getId(), "SEED");
        nameTable.put(CryptoProObjectIdentifiers.gostR28147_gcfb.getId(), "GOST28147");

        nameTable.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), "AES");
        nameTable.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), "AES");
        nameTable.put(NISTObjectIdentifiers.id_aes128_CCM.getId(), "AES");
    }

    private final AgreementFactory agreementFactory;
    private final PublicKeyConverter publicKeyConverter;
    private final PrivateKeyConverter privateKeyConverter;
    private final ParametersCreator parametersCreator;
    private final KDFOperatorFactory kdfOperatorFactory;
    private final FipsKDF.AgreementKDFParametersBuilder kdfAlgorithm;

    protected Agreement agreement;
    protected byte[] result;
    private Parameters parameters;
    private byte[] userKeyingMaterial;

    protected BaseAgreement(
        AgreementFactory agreementFactory,
        PublicKeyConverter publicKeyConverter,
        PrivateKeyConverter privateKeyConverter,
        ParametersCreator parametersCreator)
    {
        this(agreementFactory, publicKeyConverter, privateKeyConverter, parametersCreator, null);
    }

    protected BaseAgreement(
        AgreementFactory agreementFactory,
        PublicKeyConverter publicKeyConverter,
        PrivateKeyConverter privateKeyConverter,
        ParametersCreator parametersCreator,
        FipsKDF.AgreementKDFParametersBuilder kdfAlgorithm)
    {
        this.agreementFactory = agreementFactory;
        this.publicKeyConverter = publicKeyConverter;
        this.privateKeyConverter = privateKeyConverter;
        this.parametersCreator = parametersCreator;
        this.kdfAlgorithm = kdfAlgorithm;
        this.kdfOperatorFactory = new FipsKDF.AgreementOperatorFactory();
    }

    protected Key engineDoPhase(
        Key     key,
        boolean lastPhase) 
        throws InvalidKeyException, IllegalStateException
    {
        if (parameters == null)
        {
            throw new IllegalStateException("KeyAgreement not initialized");
        }

        Algorithm algorithm = parameters.getAlgorithm();

        if (!(key instanceof PublicKey))
        {
            throw new InvalidKeyException(algorithm.getName() + " key agreement requires "
                + getSimpleName(PublicKey.class) + " for doPhase");
        }

        PublicKey publicKey = (PublicKey)key;


        if (algorithm.equals(FipsDH.ALGORITHM))
        {
            AsymmetricPublicKey pubKey = publicKeyConverter.convertKey(parameters.getAlgorithm(), publicKey);

            result = calculateAgreement(pubKey);

            return new ProvDHPublicKey(new AsymmetricDHPublicKey(FipsDH.ALGORITHM, ((AsymmetricDHKey)pubKey).getDomainParameters(), new BigInteger(1, result)));
        }
        else
        {
            if (!lastPhase)
            {
                throw new IllegalStateException(algorithm.getName() + " can only be between two parties.");
            }

            AsymmetricPublicKey pubKey = publicKeyConverter.convertKey(parameters.getAlgorithm(), publicKey);

            result = calculateAgreement(pubKey);

            return null;
        }
    }

    private byte[] calculateAgreement(AsymmetricPublicKey pubKey)
        throws InvalidKeyException
    {
        try
        {
            return agreement.calculate(pubKey);
        }
        catch (IllegalKeyException e)
        {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    protected byte[] engineGenerateSecret()
        throws IllegalStateException
    {
        if (result == null)
        {
            throw new IllegalStateException("KeyAgreement not initialized");
        }

        if (kdfAlgorithm != null)
        {
            byte[] secret = result;
            byte[] keyBytes = new byte[result.length];

            FipsKDF.AgreementKDFParameters params = kdfAlgorithm.using(secret).withIV(userKeyingMaterial);

            KDFCalculator kdf = kdfOperatorFactory.createKDFCalculator(params);

            kdf.generateBytes(keyBytes, 0, keyBytes.length);

            Arrays.fill(secret, (byte)0);

            result = keyBytes;
        }

        byte[] rv = result;

        result = null;

        return rv;
    }

    protected int engineGenerateSecret(
        byte[]  sharedSecret,
        int     offset) 
        throws IllegalStateException, ShortBufferException
    {
        byte[] secret = engineGenerateSecret();

        if (sharedSecret.length - offset < secret.length)
        {
            throw new ShortBufferException(parameters.getAlgorithm().getName() + " key agreement: need "
                + secret.length + " bytes");
        }

        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);

        return secret.length;
    }

    protected SecretKey engineGenerateSecret(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        if (result == null)
        {
            throw new IllegalStateException("KeyAgreement not initialized");
        }

        byte[] secret = result;

        result = null;

        String algKey = Strings.toUpperCase(algorithm);

        if (algKey.indexOf('/') < 0)
        {
            String oidAlgorithm = algorithm;

            if (defaultOids.containsKey(algKey))
            {
                oidAlgorithm = defaultOids.get(algKey).getId();
            }

            int keySize = getKeySize(oidAlgorithm);

            if (keySize < 0)
            {
                // deal with the JSSE's inability to handle leading zeroes for FFC diffie-hellman
                if (algorithm.equals("TlsPremasterSecret")
                    && agreement.getParameters().getAlgorithm().getName().equals("DH"))
                {
                    return new SecretKeySpec(trimZeroes(secret), algorithm);
                }
                return new SecretKeySpec(secret, getAlgorithm(oidAlgorithm));   // we don't have a size for this one, just return what we have
            }

            if (kdfAlgorithm != null)
            {
                byte[] keyBytes = new byte[keySize];

                FipsKDF.AgreementKDFParameters params = kdfAlgorithm.using(secret).withIV(userKeyingMaterial);

                KDFCalculator kdf = kdfOperatorFactory.createKDFCalculator(params);

                kdf.generateBytes(keyBytes, 0, keyBytes.length);

                Arrays.fill(secret, (byte)0);

                secret = keyBytes;
            }
            else
            {
                byte[] key = new byte[keySize];

                System.arraycopy(secret, 0, key, 0, key.length);

                Arrays.fill(secret, (byte)0);

                secret = key;
            }

            if (DESUtil.isDES(oidAlgorithm))
            {
                DESUtil.setOddParity(secret);
            }

            return new SecretKeySpec(secret, getAlgorithm(oidAlgorithm));
        }
        else
        {
            String macDetails = algKey.substring(0, algKey.indexOf('/'));
            String encDetails = algKey.substring(algKey.indexOf('/') + 1);

            int macKeyLength = getKeySize(macDetails);
            int encKeyLength = getKeySize(encDetails);
            byte[] macKeyBytes = new byte[macKeyLength];
            byte[] encKeyBytes = new byte[encKeyLength];

            if (kdfAlgorithm != null)
            {
                byte[] keyBytes = new byte[macKeyLength + encKeyLength];

                FipsKDF.AgreementKDFParameters params;

                params = kdfAlgorithm.using(secret).withIV(userKeyingMaterial);

                KDFCalculator kdf = kdfOperatorFactory.createKDFCalculator(params);

                kdf.generateBytes(keyBytes, 0, keyBytes.length);

                System.arraycopy(keyBytes, 0, macKeyBytes, 0, macKeyLength);
                System.arraycopy(keyBytes, macKeyLength, encKeyBytes, 0, encKeyLength);

                Arrays.fill(secret, (byte)0);
                Arrays.fill(keyBytes, (byte)0);
            }
            else
            {
                throw new IllegalStateException("KDF is required for key agreement with confirmation");
            }

            return new AgreedKeyWithMacKey(new SecretKeySpec(encKeyBytes, getAlgorithm(encDetails)), getAlgorithm(macDetails), macKeyBytes);
        }
    }

    protected void engineInit(
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random) 
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        initFromKey(key, params, random);
    }

    protected void engineInit(
        Key             key,
        SecureRandom    random) 
        throws InvalidKeyException
    {
        try
        {
            initFromKey(key, null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {   // should never happen
            throw new InvalidKeyException("Issue processing null paramSpec: " + e.getMessage(), e);
        }
    }

    private void initFromKey(Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        parameters = parametersCreator.createParameters(true, params, random);
        if (params instanceof MQVParameterSpec)
        {
            userKeyingMaterial = ((MQVParameterSpec)params).getUserKeyingMaterial();
        }
        else if (params instanceof DHUParameterSpec)
        {
            userKeyingMaterial = ((DHUParameterSpec)params).getUserKeyingMaterial();
        }
        else if (params instanceof UserKeyingMaterialSpec)
        {
            userKeyingMaterial = ((UserKeyingMaterialSpec)params).getUserKeyingMaterial();
        }
        else
        {
            userKeyingMaterial = null;
        }

        Algorithm algorithm = parameters.getAlgorithm();

        if (!(key instanceof PrivateKey))
        {
            throw new InvalidKeyException(algorithm.getName() + " key agreement requires "
                + getSimpleName(ECPrivateKey.class) + " for initialisation");
        }

        PrivateKey privateKey = (PrivateKey)key;
        AsymmetricPrivateKey k = privateKeyConverter.convertKey(algorithm, privateKey);

        try
        {
            agreement = agreementFactory.createAgreement(k, parameters);
        }
        catch (IllegalKeyException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
        catch (FipsUnapprovedOperationError e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    private static byte[] trimZeroes(byte[] secret)
    {
        if (secret[0] != 0)
        {
            return secret;
        }
        else
        {
            int ind = 0;
            while (ind < secret.length && secret[ind] == 0)
            {
                ind++;
            }

            byte[] rv = new byte[secret.length - ind];

            System.arraycopy(secret, ind, rv, 0, rv.length);

            return rv;
        }
    }

    private static String getSimpleName(Class<?> clazz)
    {
        String fullName = clazz.getName();

        return fullName.substring(fullName.lastIndexOf('.') + 1);
    }

    private static int getKeySize(String algDetails)
    {
        if (algDetails.indexOf('[') > 0)
        {
            return (Integer.parseInt(algDetails.substring(algDetails.indexOf('[') + 1, algDetails.indexOf(']'))) + 7) / 8;
        }

        return keySizeProvider.getKeySize(algDetails);
    }

    private static String getAlgorithm(String algDetails)
    {
        if (algDetails.indexOf('[') > 0)
        {
            return algDetails.substring(0, algDetails.indexOf('['));
        }

        if (algDetails.startsWith(NISTObjectIdentifiers.aes.getId()))
        {
            return "AES";
        }
        if (algDetails.startsWith(GNUObjectIdentifiers.Serpent.getId()))
        {
            return "Serpent";
        }

        String name = nameTable.get(algDetails);

        if (name != null)
        {
            return name;
        }

        return algDetails;
    }
}
