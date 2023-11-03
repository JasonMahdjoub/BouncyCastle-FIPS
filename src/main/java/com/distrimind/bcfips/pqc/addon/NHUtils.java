package com.distrimind.bcfips.pqc.addon;

import java.io.IOException;

import com.distrimind.bcfips.asn1.bc.BCObjectIdentifiers;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.asn1.x509.SubjectPublicKeyInfo;

class NHUtils
{
    static byte[] getEncoded(NHPublicKeyParameters pubKey)
    {
        SubjectPublicKeyInfo pki;
        try
        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(BCObjectIdentifiers.newHope);
            pki = new SubjectPublicKeyInfo(algorithmIdentifier, pubKey.getPubData());

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    static NHPublicKeyParameters getPublicKey(byte[] enc)
    {
        SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(enc);

        return new NHPublicKeyParameters(pki.getPublicKeyData().getOctets());
    }
}
