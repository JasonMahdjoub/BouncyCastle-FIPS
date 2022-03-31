package com.distrimind.bcfips.jcajce.provider;

import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;

interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(ASN1ObjectIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}
