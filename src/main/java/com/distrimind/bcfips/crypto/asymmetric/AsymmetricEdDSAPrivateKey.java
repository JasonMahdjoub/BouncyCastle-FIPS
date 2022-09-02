package com.distrimind.bcfips.crypto.asymmetric;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.Destroyable;

import com.distrimind.bcfips.asn1.ASN1Encodable;
import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.ASN1Set;
import com.distrimind.bcfips.asn1.DEROctetString;
import com.distrimind.bcfips.asn1.edec.EdECObjectIdentifiers;
import com.distrimind.bcfips.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.general.EdEC;
import com.distrimind.bcfips.crypto.internal.Permissions;
import com.distrimind.bcfips.util.Arrays;

/**
 * Edwards Curve Diffie-Hellman (XDH) private keys.
 */
public final class AsymmetricEdDSAPrivateKey
    extends AsymmetricEdDSAKey
    implements Destroyable, AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[] keyData;

    private boolean hasPublicKey;
    private byte[] publicData;
    private ASN1Set attributes;
    private int hashCode;

    public AsymmetricEdDSAPrivateKey(Algorithm algorithm, byte[] keyData, byte[] publicData)
    {
        super(algorithm);
        this.keyData = Arrays.clone(keyData);
        this.hashCode = calculateHashCode();
        this.attributes = null;
        if (publicData == null)
        {
            this.hasPublicKey = false;
            this.publicData = EdEC.computePublicData(algorithm, keyData);
        }
        else
        {
            this.hasPublicKey = true;
            this.publicData = Arrays.clone(publicData);
        }
    }

    /**
     * Construct a key from an encoding of a PrivateKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    public AsymmetricEdDSAPrivateKey(byte[] encoding)
        throws IOException
    {
        this(PrivateKeyInfo.getInstance(encoding));
    }

    /**
     * Construct a key from a PrivateKeyInfo.
     *
     * @param keyInfo the PrivateKeyInfo containing the key.
     */
    public AsymmetricEdDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        super(EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm())
                    ? EdEC.Algorithm.Ed448 : EdEC.Algorithm.Ed25519);

        ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
        keyData = Arrays.clone(ASN1OctetString.getInstance(keyOcts).getOctets());

        if (keyInfo.hasPublicKey())
        {
            hasPublicKey = true;
            publicData = Arrays.clone(keyInfo.getPublicKeyData().getOctets());
        }

        if (EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            if (keyData.length != EdEC.Ed448_PRIVATE_KEY_SIZE)
            {
                throw new IllegalArgumentException("raw key data incorrect size");
            }
        }
        else
        {
            if (keyData.length != EdEC.Ed25519_PRIVATE_KEY_SIZE)
            {
                throw new IllegalArgumentException("raw key data incorrect size");
            }
        }

        this.attributes = keyInfo.getAttributes();
        this.hashCode = calculateHashCode();
    }

    public byte[] getSecret()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        KeyUtils.checkDestroyed(this);

        return Arrays.clone(keyData);
    }

    public byte[] getPublicData()
    {
        KeyUtils.checkDestroyed(this);

        return Arrays.clone(publicData);
    }

    public byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        KeyUtils.checkDestroyed(this);

        byte[] pubData = (hasPublicKey) ? publicData : null;

        if (getAlgorithm().equals(EdEC.Algorithm.Ed448))
        {
            return KeyUtils.getEncodedPrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), new DEROctetString(keyData), attributes, pubData);
        }
        else
        {
            return KeyUtils.getEncodedPrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(keyData), attributes, pubData);
        }
    }

    public void destroy()
    {
        checkApprovedOnlyModeStatus();

        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.clear(keyData);
            if (publicData != null)
            {
                Arrays.clear(publicData);
            }
            this.publicData = null;
            this.hasPublicKey = false;
            this.attributes = null;
            this.hashCode = -1;
            super.zeroize();
        }
    }

    public boolean isDestroyed()
    {
        checkApprovedOnlyModeStatus();

        return hasBeenDestroyed.get();
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricEdDSAPrivateKey))
        {
            return false;
        }

        AsymmetricEdDSAPrivateKey other = (AsymmetricEdDSAPrivateKey)o;

        if (this.isDestroyed() || other.isDestroyed())
        {
            return false;
        }

        if (!Arrays.areEqual(keyData, other.keyData))
        {
            return false;
        }

        return this.getAlgorithm().equals(other.getAlgorithm());
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = getAlgorithm().hashCode();
        result = 31 * result + Arrays.hashCode(keyData);
        return result;
    }

    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        destroy();
    }
}
