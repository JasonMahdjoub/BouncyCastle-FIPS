package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import com.distrimind.bcfips.crypto.fips.FipsOutputXOFCalculator;
import com.distrimind.bcfips.crypto.fips.FipsSHS;
import com.distrimind.bcfips.crypto.fips.FipsXOFOperatorFactory;
import com.distrimind.bcfips.util.Arrays;

/**
 * A processor with associated builders for doing secret key transformation using
 * a PQC KEM algorithm.
 */
public class PQCSecretKeyProcessor
    implements SecretKeyProcessor
{
    /**
     * Party U (initiator) processor builder.
     */
    public static class PartyUBuilder
    {
        private final AsymmetricCipherKeyPair aKp;
        private final EncapsulatedSecretExtractor extractor;

        private byte[] sharedInfo = null;

        public PartyUBuilder(KEMParameters kemParameters, SecureRandom random)
        {
            if (kemParameters instanceof CMCEParameters)
            {
                CMCEKeyPairGenerator kpGen = new CMCEKeyPairGenerator();

                kpGen.init(new CMCEKeyGenerationParameters(random, (CMCEParameters)kemParameters));

                aKp = kpGen.generateKeyPair();

                extractor = new CMCEKEMExtractor((CMCEPrivateKeyParameters)aKp.getPrivate());
            }
            else
            {
                FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();

                kpGen.init(new FrodoKeyGenerationParameters(random, (FrodoParameters)kemParameters));

                aKp = kpGen.generateKeyPair();

                extractor = new FrodoKEMExtractor((FrodoPrivateKeyParameters)aKp.getPrivate());
            }
        }

        public PartyUBuilder withSharedInfo(byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartA()
        {
            Object pub = aKp.getPublic();
            if (pub instanceof CMCEPublicKeyParameters)
            {
                return ((CMCEPublicKeyParameters)pub).getEncoded();
            }
            else
            {
                return ((FrodoPublicKeyParameters)pub).getEncoded();
            }
        }

        public SecretKeyProcessor build(byte[] partB)
        {
            // secret erased in constructor.
            return new PQCSecretKeyProcessor(extractor.extractSecret(partB), sharedInfo);
        }
    }

    /**
     * Party V (responder) processor builder.
     */
    public static class PartyVBuilder
    {
        private final KEMParameters kemParameters;
        protected final SecureRandom random;

        private byte[] sharedInfo = null;
        private byte[] sharedSecret = null;
        private SecretWithEncapsulationImpl secretWithEncapsulation;
        private boolean used = false;

        public PartyVBuilder(KEMParameters kemParameters, SecureRandom random)
        {
            this.kemParameters = kemParameters;
            this.random = random;
        }

        public PartyVBuilder withSharedInfo(byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartB(byte[] partUContribution)
        {
            if (kemParameters instanceof CMCEParameters)
            {
                CMCEPublicKeyParameters otherPub = new CMCEPublicKeyParameters((CMCEParameters)kemParameters, partUContribution);

                CMCEKEMGenerator kemGenerator = new CMCEKEMGenerator(random);

                secretWithEncapsulation = (SecretWithEncapsulationImpl)kemGenerator.generateEncapsulated(otherPub);
            }
            else
            {
                FrodoPublicKeyParameters otherPub = new FrodoPublicKeyParameters((FrodoParameters)kemParameters, partUContribution);

                FrodoKEMGenerator kemGenerator = new FrodoKEMGenerator(random);

                secretWithEncapsulation = (SecretWithEncapsulationImpl)kemGenerator.generateEncapsulated(otherPub);
            }

            return secretWithEncapsulation.getEncapsulation();
        }

        public SecretKeyProcessor build()
        {
            PQCSecretKeyProcessor pqcSecretKeyProcessor = new PQCSecretKeyProcessor(secretWithEncapsulation.getSecret(), sharedInfo);

            try
            {
                secretWithEncapsulation.destroy();
            }
            catch (DestroyFailedException e)
            {
                throw new IllegalStateException("unable to clean up secret data: " + e.getMessage(), e);
            }
            return pqcSecretKeyProcessor;
        }
    }

    private final FipsOutputXOFCalculator xofOperator;

    private PQCSecretKeyProcessor(byte[] secret, byte[] shared)
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
