package com.distrimind.bcfips.pqc.addon;

class NHAgreement
{
    private NHPrivateKeyParameters privKey;

    public void init(NHPrivateKeyParameters param)
    {
        privKey = param;
    }

    public byte[] calculateAgreement(NHPublicKeyParameters otherPublicKey)
    {
        NHPublicKeyParameters pubKey = otherPublicKey;

        byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];

        NewHope.sharedA(sharedValue, privKey.secData, pubKey.pubData);

        return sharedValue;
    }
}
