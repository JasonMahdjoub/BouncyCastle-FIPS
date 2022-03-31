package com.distrimind.bcfips.jcajce.provider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.distrimind.bcfips.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bcfips.asn1.x509.SubjectPublicKeyInfo;

interface AsymmetricKeyInfoConverter
{
    PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException;

    PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException;
}
