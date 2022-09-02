package com.distrimind.bcfips.crypto.fips;

import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.params.ParametersWithIV;
import com.distrimind.bcfips.crypto.internal.params.ParametersWithRandom;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.internal.BlockCipher;
import com.distrimind.bcfips.crypto.internal.BufferedBlockCipher;
import com.distrimind.bcfips.crypto.internal.CipherParameters;
import com.distrimind.bcfips.crypto.internal.EngineProvider;
import com.distrimind.bcfips.crypto.internal.ValidatedSymmetricKey;
import com.distrimind.bcfips.crypto.internal.modes.AEADBlockCipher;
import com.distrimind.bcfips.crypto.internal.modes.CBCBlockCipher;
import com.distrimind.bcfips.crypto.internal.modes.CCMBlockCipher;
import com.distrimind.bcfips.crypto.internal.modes.CFBBlockCipher;
import com.distrimind.bcfips.crypto.internal.modes.GCMBlockCipher;
import com.distrimind.bcfips.crypto.internal.modes.NISTCTSBlockCipher;
import com.distrimind.bcfips.crypto.internal.modes.OFBBlockCipher;
import com.distrimind.bcfips.crypto.internal.modes.SICBlockCipher;
import com.distrimind.bcfips.crypto.internal.paddings.ISO10126d2Padding;
import com.distrimind.bcfips.crypto.internal.paddings.ISO7816d4Padding;
import com.distrimind.bcfips.crypto.internal.paddings.PKCS7Padding;
import com.distrimind.bcfips.crypto.internal.paddings.PaddedBufferedBlockCipher;
import com.distrimind.bcfips.crypto.internal.paddings.TBCPadding;
import com.distrimind.bcfips.crypto.internal.paddings.X923Padding;
import com.distrimind.bcfips.util.Pack;
import com.distrimind.bcfips.util.Strings;

class BlockCipherUtils
{
    private static SecureRandom defaultRandomPadder;

    static BufferedBlockCipher createBlockCipher(EngineProvider<BlockCipher> provider, FipsParameters parameter)
    {
        BlockCipher cipher = provider.createEngine();
        Padding padding = (Padding)parameter.getAlgorithm().additionalVariation();

        switch (((Mode)parameter.getAlgorithm().basicVariation()))
        {
        case ECB:
            break;
        case CBC:
            if (padding != Padding.CS1 && padding != Padding.CS2 && padding != Padding.CS3)
            {
                cipher = new CBCBlockCipher(cipher);
            }
            break;
        case CFB8:
            cipher = new CFBBlockCipher(cipher, 8);
            break;
        case CFB64:
            cipher = new CFBBlockCipher(cipher, 64);
            break;
        case CFB128:
            cipher = new CFBBlockCipher(cipher, 128);
            break;
        case OFB64:
            cipher = new OFBBlockCipher(cipher, 64);
            break;
        case OFB128:
            cipher = new OFBBlockCipher(cipher, 128);
            break;
        case CTR:
            cipher = new SICBlockCipher(cipher);
            break;
        default:
            throw new IllegalArgumentException("Unknown mode passed to createBlockCipher: " + parameter.getAlgorithm());
        }

        if (padding != null)
        {
            switch (padding)
            {
            case PKCS7:
                return new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
            case ISO7816_4:
                return new PaddedBufferedBlockCipher(cipher, new ISO7816d4Padding());
            case ISO10126_2:
                 return new PaddedBufferedBlockCipher(cipher, new ISO10126d2Padding());
            case TBC:
                return new PaddedBufferedBlockCipher(cipher, new TBCPadding());
            case X923:
                return new PaddedBufferedBlockCipher(cipher, new X923Padding());
            case CS1:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS1, cipher);
            case CS2:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS2, cipher);
            case CS3:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS3, cipher);
            default:
                throw new IllegalArgumentException("Unknown padding passed to createBlockCipher: " + parameter.getAlgorithm());
            }
        }

        return new BufferedBlockCipher(cipher);
    }

    static BufferedBlockCipher createStandardCipher(boolean forEncryption, final ValidatedSymmetricKey key, EngineProvider<BlockCipher> engineProvider, com.distrimind.bcfips.crypto.ParametersWithIV parameters, SecureRandom random)
    {
        BufferedBlockCipher cipher = BlockCipherUtils.createBlockCipher(engineProvider, (FipsParameters)parameters);
        CipherParameters cipherParameters = Utils.getKeyParameter(key);

        if (parameters.getIV() != null)
        {
            cipherParameters = new ParametersWithIV(cipherParameters, parameters.getIV());
        }

        if (((FipsAlgorithm)parameters.getAlgorithm()).additionalVariation() instanceof Padding)
        {
            Padding padding = (Padding)((FipsAlgorithm)parameters.getAlgorithm()).additionalVariation();

            if (padding.getBasePadding().requiresRandom() && forEncryption)
            {
                if (random != null)
                {
                    cipherParameters = new ParametersWithRandom(cipherParameters, random);
                }
                else
                {
                    try
                    {
                        cipherParameters = new ParametersWithRandom(cipherParameters, CryptoServicesRegistrar.getSecureRandom());
                    }
                    catch (IllegalStateException e)
                    {
                        cipherParameters = new ParametersWithRandom(cipherParameters, getDefaultRandomPadder());
                    }
                }
            }
        }

        cipher.init(forEncryption, cipherParameters);

        return cipher;
    }

    static AEADBlockCipher createAEADCipher(FipsAlgorithm algorithm, EngineProvider<BlockCipher> provider)
    {
        AEADBlockCipher  cipher;

        switch (((Mode)algorithm.basicVariation()))
        {
        case CCM:
            cipher = new CCMBlockCipher(provider.createEngine());
            break;
        case GCM:
            cipher = new GCMBlockCipher(provider.createEngine());
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to createAEADCipher: " + algorithm);
        }

        return cipher;
    }

    static synchronized SecureRandom getDefaultRandomPadder()
    {
        if (defaultRandomPadder == null)
        {
             defaultRandomPadder = FipsDRBG.SHA512.fromDefaultEntropy().
                 setPersonalizationString(Strings.toByteArray("Bouncy Castle FIPS Default Padder"))
                 .build(Pack.longToBigEndian(System.currentTimeMillis()),false);
        }

        return defaultRandomPadder;
    }
}
