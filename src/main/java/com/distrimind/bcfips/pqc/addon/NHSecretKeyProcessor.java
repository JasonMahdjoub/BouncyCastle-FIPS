package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.distrimind.bcfips.crypto.fips.FipsOutputXOFCalculator;
import com.distrimind.bcfips.crypto.fips.FipsSHS;
import com.distrimind.bcfips.crypto.fips.FipsXOFOperatorFactory;
import com.distrimind.bcfips.util.Arrays;

/**
 * A processor with associated builders for doing secret key transformation using
 * the New Hope algorithm.
 */
public class NHSecretKeyProcessor
    implements SecretKeyProcessor
{
    /**
     * Party U (initiator) processor builder.
     */
    public static class PartyUBuilder
    {
        private final AsymmetricCipherKeyPair aKp;
        private final NHAgreement agreement = new NHAgreement();

        private byte[] sharedInfo = null;
        private boolean used = false;

        public PartyUBuilder(SecureRandom random)
        {
            NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

            kpGen.init(random);

            aKp = kpGen.generateKeyPair();

            agreement.init((NHPrivateKeyParameters)aKp.getPrivate());
        }

        public PartyUBuilder withSharedInfo(byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartA()
        {
            return NHUtils.getEncoded((NHPublicKeyParameters)aKp.getPublic());
        }

        public SecretKeyProcessor build(byte[] partB)
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return new NHSecretKeyProcessor(agreement.calculateAgreement(NHUtils.getPublicKey(partB)), sharedInfo);
        }
    }

    /**
     * Party V (responder) processor builder.
     */
    public static class PartyVBuilder
    {
        protected final SecureRandom random;

        private byte[] sharedInfo = null;
        private byte[] sharedSecret = null;
        private boolean used = false;

        public PartyVBuilder(SecureRandom random)
        {
            this.random = random;
        }

        public PartyVBuilder withSharedInfo(byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartB(byte[] partUContribution)
        {
            NHExchangePairGenerator exchGen = new NHExchangePairGenerator(random);

            ExchangePair bEp = exchGen.generateExchange(NHUtils.getPublicKey(partUContribution));

            sharedSecret = bEp.getSharedValue();

            return NHUtils.getEncoded((NHPublicKeyParameters)bEp.getPublicKey());
        }

        public SecretKeyProcessor build()
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return new NHSecretKeyProcessor(sharedSecret, sharedInfo);
        }
    }

    private final FipsOutputXOFCalculator xofOperator;

    private NHSecretKeyProcessor(byte[] secret, byte[] shared)
    {
        FipsXOFOperatorFactory xofOperatorFactory = new FipsSHS.XOFOperatorFactory();

        xofOperator = xofOperatorFactory.createOutputXOFCalculator(FipsSHS.SHAKE256);

        try
        {
            OutputStream xofOut = xofOperator.getFunctionStream();

            xofOut.write(secret);

            if (shared != null)
            {
                xofOut.write(shared);
            }

            xofOut.close();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to initialize XOF: " + e.getMessage(), e);
        }

        Arrays.fill(secret, (byte)0);
    }

    @Override
    public SecretKey processKey(SecretKey initialKey)
    {
        byte[] keyBytes = initialKey.getEncoded();
        byte[] xorBytes = xofOperator.getFunctionOutput(keyBytes.length);

        xor(keyBytes, xorBytes);

        Arrays.fill(xorBytes, (byte)0);

        return new SecretKeySpec(keyBytes, initialKey.getAlgorithm());
    }

    private static void xor(byte[] a, byte[] b)
    {
        for (int i = 0; i != a.length; i++)
        {
            a[i] ^= b[i];
        }
    }
}
