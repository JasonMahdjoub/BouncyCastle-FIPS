package com.distrimind.bcfips.crypto.general;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import com.distrimind.bcfips.crypto.internal.DSA;
import com.distrimind.bcfips.crypto.internal.Digest;
import com.distrimind.bcfips.crypto.internal.io.DigestOutputStream;
import com.distrimind.bcfips.asn1.ASN1EncodableVector;
import com.distrimind.bcfips.asn1.ASN1Encoding;
import com.distrimind.bcfips.asn1.ASN1Integer;
import com.distrimind.bcfips.asn1.DEROctetString;
import com.distrimind.bcfips.asn1.DERSequence;
import com.distrimind.bcfips.crypto.OperatorNotReadyException;
import com.distrimind.bcfips.crypto.OutputSignerUsingSecureRandom;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.PlainInputProcessingException;
import com.distrimind.bcfips.crypto.UpdateOutputStream;

class DSAOutputSigner<T extends Parameters>
    implements OutputSignerUsingSecureRandom<T>
{

    private final com.distrimind.bcfips.crypto.internal.DSA dsa;
    private final Digest digest;
    private final T parameter;
    private final Initializer initializer;
    private final boolean ready;
    private final boolean reverse;

    DSAOutputSigner(com.distrimind.bcfips.crypto.internal.DSA dsa, Digest digest, T parameter, Initializer initializer)
    {
        this(false, dsa, digest, parameter, initializer, false);
    }

    DSAOutputSigner(com.distrimind.bcfips.crypto.internal.DSA dsa, Digest digest, T parameter, Initializer initializer, boolean reverse)
    {
        this(false, dsa, digest, parameter, initializer, reverse);
    }

    DSAOutputSigner(boolean ready, com.distrimind.bcfips.crypto.internal.DSA dsa, Digest digest, T parameter, Initializer initializer, boolean reverse)
    {
        this.ready = ready;
        this.dsa = dsa;
        this.digest = digest;
        this.parameter = parameter;
        this.initializer = initializer;
        this.reverse = reverse;
    }

    public T getParameters()
    {
        return parameter;
    }

    public UpdateOutputStream getSigningStream()
    {
        if (!ready)
        {
            throw new OperatorNotReadyException("Signer requires a SecureRandom to be attached before use");
        }

        return new DigestOutputStream(digest);
    }

    public byte[] getSignature()
        throws PlainInputProcessingException
    {
        byte[] m = new byte[digest.getDigestSize()];

        digest.doFinal(m, 0);

        try
        {
            return encode(dsa.generateSignature(m));
        }
        catch (Exception e)
        {
            throw new PlainInputProcessingException("Unable to create signature: " + e.getMessage(), e);
        }
    }

    public int getSignature(byte[] output, int off)
        throws PlainInputProcessingException
    {
        byte[] sig = getSignature();

        System.arraycopy(sig, 0, output, off, sig.length);

        return sig.length;
    }

    private byte[] encode(
        BigInteger[] rs)
        throws IOException
    {
        if (dsa instanceof EcGost3410Signer || dsa instanceof Gost3410Signer)
        {
            byte[]          sigBytes = new byte[64];
            byte[]          r = rs[0].toByteArray();
            byte[]          s = rs[1].toByteArray();

            if (s[0] != 0)
            {
                System.arraycopy(s, 0, sigBytes, 32 - s.length, s.length);
            }
            else
            {
                System.arraycopy(s, 1, sigBytes, 32 - (s.length - 1), s.length - 1);
            }

            if (r[0] != 0)
            {
                System.arraycopy(r, 0, sigBytes, 64 - r.length, r.length);
            }
            else
            {
                System.arraycopy(r, 1, sigBytes, 64 - (r.length - 1), r.length - 1);
            }

            return sigBytes;
        }
        else if (dsa instanceof DSTU4145Signer)
        {
            byte[] r = rs[0].toByteArray();
            byte[] s = rs[1].toByteArray();

            byte[] sigBytes = new byte[(r.length > s.length ? r.length * 2 : s.length * 2)];

            System.arraycopy(s, 0, sigBytes, (sigBytes.length / 2) - s.length, s.length);
            System.arraycopy(r, 0, sigBytes, sigBytes.length - r.length, r.length);

            if (reverse)
            {
                DSAUtils.reverseBytes(sigBytes);
            }

            return new DEROctetString(sigBytes).getEncoded();
        }
        else
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new ASN1Integer(rs[0]));
            v.add(new ASN1Integer(rs[1]));

            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        }
    }

    public DSAOutputSigner<T> withSecureRandom(SecureRandom random)
    {
        initializer.initialize(dsa, random);

        return new DSAOutputSigner<T>(true, dsa, digest, parameter, initializer, reverse);
    }

    static interface Initializer
    {
        void initialize(DSA signer, SecureRandom random);
    }
}
