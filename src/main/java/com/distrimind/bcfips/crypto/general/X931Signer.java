package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.internal.AsymmetricBlockCipher;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.signers.BaseX931Signer;
import com.distrimind.bcfips.crypto.internal.util.ISOTrailers;
import com.distrimind.bcfips.crypto.fips.FipsRSA;

/**
 * X9.31-1998 - signing using a hash.
 * <p>
 * The message digest hash, H, is encapsulated to form a byte string as follows
 * <pre>
 * EB = 06 || PS || 0xBA || H || TRAILER
 * </pre>
 * where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|, and TRAILER is the ISO/IEC 10118 part number† for the digest. The byte string, EB, is converted to an integer value, the message representative, f.
 */
class X931Signer
    extends BaseX931Signer
{
    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param digest digest to use.
     */
    public X931Signer(
        Digest digest)
    {
        super((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine(), digest, ISOTrailers.noTrailerAvailable(digest));
    }

}
