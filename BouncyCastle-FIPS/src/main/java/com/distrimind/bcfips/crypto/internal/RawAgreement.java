package com.distrimind.bcfips.crypto.internal;

public interface RawAgreement
{
    void init(CipherParameters parameters);

    int getAgreementSize();

    void calculateAgreement(CipherParameters publicKey, byte[] buf, int off);
}
