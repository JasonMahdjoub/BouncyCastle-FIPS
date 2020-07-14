package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.fips.FipsRSA;
import com.distrimind.bcfips.crypto.internal.AsymmetricBlockCipher;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.signers.BaseISO9796d2Signer;
import com.distrimind.bcfips.crypto.internal.util.ISOTrailers;

class ISO9796d2Signer
    extends BaseISO9796d2Signer
{
    /**
     * Generate a signer for the with either implicit or explicit trailers
     * for ISO9796-2.
     *
     * @param digest digest to use.
     */
    public ISO9796d2Signer(
        Digest digest)
    {
        super((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine(), digest, ISOTrailers.noTrailerAvailable(digest));
    }
}
