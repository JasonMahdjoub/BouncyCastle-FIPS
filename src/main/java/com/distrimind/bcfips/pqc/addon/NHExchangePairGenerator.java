package com.distrimind.bcfips.pqc.addon;

import java.security.SecureRandom;

class NHExchangePairGenerator
{
    private final SecureRandom random;

    public NHExchangePairGenerator(SecureRandom random)
    {
        this.random = random;
    }

    public ExchangePair GenerateExchange(NHPublicKeyParameters senderPublicKey)
    {
        return generateExchange(senderPublicKey);
    }

    public ExchangePair generateExchange(NHPublicKeyParameters senderPublicKey)
    {
        NHPublicKeyParameters pubKey = senderPublicKey;

        byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];
        byte[] publicKeyValue = new byte[NewHope.SENDB_BYTES];

        NewHope.sharedB(random, sharedValue, publicKeyValue, pubKey.pubData);

        return new ExchangePair(new NHPublicKeyParameters(publicKeyValue), sharedValue);
    }
}
