package com.distrimind.bcfips.pqc.addon;

import java.security.SecureRandom;

import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.crypto.util.DEROtherInfo;

/**
 * OtherInfo Generator for which can be used for populating the SuppPrivInfo field used to provide shared
 * secret data used with NIST SP 800-56A agreement algorithms.
 */
public class NHOtherInfoGenerator
{
    protected final DEROtherInfo.Builder otherInfoBuilder;
    protected final SecureRandom random;

    protected boolean used = false;

    /**
     * Create a basic builder with just the compulsory fields.
     *
     * @param algorithmID the algorithm associated with this invocation of the KDF.
     * @param partyUInfo  sender party info.
     * @param partyVInfo  receiver party info.
     * @param random a source of randomness.
     */
    public NHOtherInfoGenerator(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
    {
        this.otherInfoBuilder = new DEROtherInfo.Builder(algorithmID, partyUInfo, partyVInfo);
        this.random = random;
    }

    /**
     * Party U (initiator) generation.
     */
    public static class PartyU
        extends NHOtherInfoGenerator
    {
        private AsymmetricCipherKeyPair aKp;
        private NHAgreement agreement = new NHAgreement();

        public PartyU(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
        {
            super(algorithmID, partyUInfo, partyVInfo, random);

            NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

            kpGen.init(random);

            aKp = kpGen.generateKeyPair();

            agreement.init((NHPrivateKeyParameters)aKp.getPrivate());
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public NHOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        public byte[] getSuppPrivInfoPartA()
        {
            return NHUtils.getEncoded((NHPublicKeyParameters)aKp.getPublic());
        }

        public DEROtherInfo generate(byte[] suppPrivInfoPartB)
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            this.otherInfoBuilder.withSuppPrivInfo(agreement.calculateAgreement(NHUtils.getPublicKey(suppPrivInfoPartB)));

            return otherInfoBuilder.build();
        }
    }

    /**
     * Party V (responder) generation.
     */
    public static class PartyV
        extends NHOtherInfoGenerator
    {
        public PartyV(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo, SecureRandom random)
        {
            super(algorithmID, partyUInfo, partyVInfo, random);
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public NHOtherInfoGenerator withSuppPubInfo(byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        public byte[] getSuppPrivInfoPartB(byte[] suppPrivInfoPartA)
        {
            NHExchangePairGenerator exchGen = new NHExchangePairGenerator(random);

            ExchangePair bEp = exchGen.generateExchange(NHUtils.getPublicKey(suppPrivInfoPartA));

            this.otherInfoBuilder.withSuppPrivInfo(bEp.getSharedValue());

            return NHUtils.getEncoded((NHPublicKeyParameters)bEp.getPublicKey());
        }

        public DEROtherInfo generate()
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return otherInfoBuilder.build();
        }
    }
}
