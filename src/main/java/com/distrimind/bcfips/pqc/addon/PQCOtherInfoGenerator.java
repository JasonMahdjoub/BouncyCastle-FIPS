package com.distrimind.bcfips.pqc.addon;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;

import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.crypto.util.DEROtherInfo;

/**
 * Post-Quantum OtherInfo Generator for which can be used for populating the SuppPrivInfo field used to provide shared
 * secret data used with NIST SP 800-56A agreement algorithms.
 */
public class PQCOtherInfoGenerator
{
    protected final DEROtherInfo.Builder otherInfoBuilder;
    protected final SecureRandom random;
    protected final KEMParameters kemParameters;

    /**
     * Create a basic builder with just the compulsory fields.
     *
     * @param kemParameters the PQC KEM parameters to use.
     * @param algorithmID   the algorithm associated with this invocation of the KDF.
     * @param partyUInfo    sender party info.
     * @param partyVInfo    receiver party info.
     * @param random        a source of randomness.
     */
    public PQCOtherInfoGenerator(KEMParameters kemParameters, AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
    {
        this.kemParameters = kemParameters;
        this.otherInfoBuilder = new DEROtherInfo.Builder(algorithmID, partyUInfo, partyVInfo);
        this.random = random;
    }

    /**
     * Party U (initiator) generation.
     */
    public static class PartyU
        extends PQCOtherInfoGenerator
    {
        private AsymmetricCipherKeyPair aKp;
        private EncapsulatedSecretExtractor extractor;

        public PartyU(KEMParameters kemParameters, AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
        {
            super(kemParameters, algorithmID, partyUInfo, partyVInfo, random);

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

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public PQCOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        /**
         * Return the part A information (Party U's public key).
         *
         * @return part A.
         */
        public byte[] getSuppPrivInfoPartA()
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

        /**
         * Generate the OtherInfo decrypting the contents of suppPrivInfoPartB and putting it in the
         * suppPrivInfo field of the OtherInfo structure.
         *
         * @param suppPrivInfoPartB an encrypted packet
         * @return
         */
        public DEROtherInfo generate(byte[] suppPrivInfoPartB)
        {
            byte[] secret = extractor.extractSecret(suppPrivInfoPartB);

            this.otherInfoBuilder.withSuppPrivInfo(secret);

            Arrays.fill(secret, (byte)0);

            return otherInfoBuilder.build();
        }
    }

    /**
     * Party V (responder) generation.
     */
    public static class PartyV
        extends PQCOtherInfoGenerator
    {
        private SecretWithEncapsulationImpl secretWithEncapsulation;

        public PartyV(KEMParameters kemParameters, AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
        {
            super(kemParameters, algorithmID, partyUInfo, partyVInfo, random);
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public PQCOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        /**
         * Return the part B information - a secret encrypted using the encoded public key passed in suppPrivInfoPartA.
         *
         * @param suppPrivInfoPartA encoding of Party U's public key.
         * @return an encrypted secret.
         */
        public byte[] getSuppPrivInfoPartB(byte[] suppPrivInfoPartA)
        {
            if (kemParameters instanceof CMCEParameters)
            {
                CMCEPublicKeyParameters otherPub = new CMCEPublicKeyParameters((CMCEParameters)kemParameters, suppPrivInfoPartA);

                CMCEKEMGenerator kemGenerator = new CMCEKEMGenerator(random);

                secretWithEncapsulation = (SecretWithEncapsulationImpl)kemGenerator.generateEncapsulated(otherPub);
            }
            else
            {
                FrodoPublicKeyParameters otherPub = new FrodoPublicKeyParameters((FrodoParameters)kemParameters, suppPrivInfoPartA);

                FrodoKEMGenerator kemGenerator = new FrodoKEMGenerator(random);

                secretWithEncapsulation = (SecretWithEncapsulationImpl)kemGenerator.generateEncapsulated(otherPub);
            }

            return secretWithEncapsulation.getEncapsulation();
        }

        public DEROtherInfo generate()
        {
            this.otherInfoBuilder.withSuppPrivInfo(secretWithEncapsulation.getSecret());

            try
            {
                secretWithEncapsulation.destroy();
            }
            catch (DestroyFailedException e)
            {
                throw new IllegalStateException("unable to clean up secret data: " + e.getMessage(), e);
            }

            return otherInfoBuilder.build();
        }
    }
}
