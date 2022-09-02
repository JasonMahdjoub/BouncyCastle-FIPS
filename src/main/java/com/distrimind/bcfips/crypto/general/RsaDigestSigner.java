package com.distrimind.bcfips.crypto.general;

import java.util.Hashtable;

import com.distrimind.bcfips.crypto.internal.AsymmetricBlockCipher;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.encodings.PKCS1Encoding;
import com.distrimind.bcfips.crypto.internal.signers.BaseRsaDigestSigner;
import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;
import com.distrimind.bcfips.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bcfips.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bcfips.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.distrimind.bcfips.asn1.x509.X509ObjectIdentifiers;
import com.distrimind.bcfips.crypto.fips.FipsRSA;

class RsaDigestSigner
    extends BaseRsaDigestSigner
{
    private static final Hashtable oidMap = new Hashtable();

    /*
     * Load OID table.
     */
    static
    {
        oidMap.put("RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128);
        oidMap.put("RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160);
        oidMap.put("RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);

        oidMap.put("SHA-1", X509ObjectIdentifiers.id_SHA1);
        oidMap.put("SHA-224", NISTObjectIdentifiers.id_sha224);
        oidMap.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        oidMap.put("SHA-384", NISTObjectIdentifiers.id_sha384);
        oidMap.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        oidMap.put("SHA-512/224", NISTObjectIdentifiers.id_sha512_224);
        oidMap.put("SHA-512/256", NISTObjectIdentifiers.id_sha512_256);

        oidMap.put("MD2", PKCSObjectIdentifiers.md2);
        oidMap.put("MD4", PKCSObjectIdentifiers.md4);
        oidMap.put("MD5", PKCSObjectIdentifiers.md5);
    }

    public RsaDigestSigner(
        Digest digest)
    {
        this(digest, (ASN1ObjectIdentifier)oidMap.get(digest.getAlgorithmName()));
    }

    public RsaDigestSigner(
        Digest digest,
        ASN1ObjectIdentifier digestOid)
    {
        super(new PKCS1Encoding((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine()), digest, digestOid);
    }
}
