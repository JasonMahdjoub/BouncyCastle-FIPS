package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.fips.FipsRSA;
import com.distrimind.bcfips.crypto.internal.AsymmetricBlockCipher;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.signers.BaseISO9796d2PSSSigner;
import com.distrimind.bcfips.crypto.internal.util.ISOTrailers;

class ISO9796d2PSSSigner
    extends BaseISO9796d2PSSSigner
{
    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param digest digest to use.
     */
    public ISO9796d2PSSSigner(
        Digest digest,
        int    saltLength)
    {
        super((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine(), digest, saltLength, ISOTrailers.noTrailerAvailable(digest));
    }

    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param digest digest to use.
     */
    public ISO9796d2PSSSigner(
        Digest digest,
        byte[] salt)
    {
        super((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine(), digest, salt, ISOTrailers.noTrailerAvailable(digest));
    }
}
