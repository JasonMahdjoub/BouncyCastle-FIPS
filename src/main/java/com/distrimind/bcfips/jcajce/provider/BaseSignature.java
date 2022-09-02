package com.distrimind.bcfips.jcajce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import com.distrimind.bcfips.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bcfips.asn1.x509.X509ObjectIdentifiers;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricKey;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.OutputSigner;
import com.distrimind.bcfips.crypto.OutputVerifier;
import com.distrimind.bcfips.crypto.Parameters;
import com.distrimind.bcfips.crypto.SignatureOperatorFactory;
import com.distrimind.bcfips.crypto.UpdateOutputStream;
import com.distrimind.bcfips.crypto.fips.FipsAlgorithm;
import com.distrimind.bcfips.crypto.fips.FipsDigestAlgorithm;
import com.distrimind.bcfips.crypto.fips.FipsRSA;

class BaseSignature
    extends SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private static final byte   TRAILER_IMPLICIT    = (byte)0xBC;

    private final SignatureOperatorFactory operatorFactory;
    private final PublicKeyConverter publicKeyConverter;
    private final PrivateKeyConverter privateKeyConverter;
    private final BouncyCastleFipsProvider fipsProvider;
    private final AlgorithmParameterSpec originalSpec;

    protected Parameters     parameters;
    protected OutputVerifier verifier;
    protected OutputSigner   signer;
    protected UpdateOutputStream dataStream;

    protected AlgorithmParameters engineParams;
    protected AlgorithmParameterSpec paramSpec;

    protected AsymmetricKey key;

    protected BaseSignature(
        BouncyCastleFipsProvider fipsProvider,
        SignatureOperatorFactory operatorFactory,
        PublicKeyConverter publicKeyConverter,
        PrivateKeyConverter privateKeyConverter,
        Parameters parameters)
    {
        this.fipsProvider = fipsProvider;
        this.operatorFactory = operatorFactory;
        this.publicKeyConverter = publicKeyConverter;
        this.privateKeyConverter = privateKeyConverter;
        this.parameters = parameters;
        this.originalSpec = null;
    }

    protected BaseSignature(
        BouncyCastleFipsProvider fipsProvider,
        SignatureOperatorFactory operatorFactory,
        PublicKeyConverter publicKeyConverter,
        PrivateKeyConverter privateKeyConverter,
        Parameters parameters,
        AlgorithmParameterSpec paramSpec)
    {
        this.fipsProvider = fipsProvider;
        this.operatorFactory = operatorFactory;
        this.publicKeyConverter = publicKeyConverter;
        this.privateKeyConverter = privateKeyConverter;
        this.parameters = parameters;
        this.paramSpec = paramSpec;
        this.originalSpec = paramSpec;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        key = publicKeyConverter.convertKey(parameters.getAlgorithm(), publicKey);

        verifier = operatorFactory.createVerifier((AsymmetricPublicKey)key, parameters);
        dataStream = verifier.getVerifyingStream();
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        key = privateKeyConverter.convertKey(parameters.getAlgorithm(), privateKey);

        try
        {
            signer = Utils.addRandomIfNeeded(operatorFactory.createSigner((AsymmetricPrivateKey)key, parameters), fipsProvider.getDefaultSecureRandom());
            dataStream = signer.getSigningStream();
        }
        catch (Exception e)
        {
            throw new InvalidKeyException("Cannot initialize for signing: " + e.getMessage(), e);
        }
    }

    protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        key = privateKeyConverter.convertKey(parameters.getAlgorithm(), privateKey);
              // TODO: should change addRandomIfNeeded in 1.1 (maybe? - it's correct in this case but is it always?
        signer = Utils.addRandomIfNeeded(operatorFactory.createSigner((AsymmetricPrivateKey)key, parameters), random != null ? random : fipsProvider.getDefaultSecureRandom());
        dataStream = signer.getSigningStream();
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        dataStream.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        dataStream.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return signer.getSignature();
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString(), e);
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        try
        {
            return verifier.isVerified(sigBytes);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString(), e);
        }
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            if (originalSpec != null)
            {
                params = originalSpec;
            }
            else
            {
                return;
            }
        }

        if (params instanceof PSSParameterSpec)
        {
            PSSParameterSpec newParamSpec = (PSSParameterSpec)params;
            if (originalSpec instanceof PSSParameterSpec)
            {
                PSSParameterSpec origPssSpec = (PSSParameterSpec)originalSpec;

                if (originalSpec != PSSParameterSpec.DEFAULT && !DigestUtil.isSameDigest(origPssSpec.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("Parameter must be using " + origPssSpec.getDigestAlgorithm());
                }
            }
            if (!newParamSpec.getMGFAlgorithm().equalsIgnoreCase("MGF1") && !newParamSpec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId()))
            {
                throw new InvalidAlgorithmParameterException("Unknown mask generation function specified");
            }

            if (!(newParamSpec.getMGFParameters() instanceof MGF1ParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("Unknown MGF parameters");
            }

            MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)newParamSpec.getMGFParameters();

            if (!DigestUtil.isSameDigest(mgfParams.getDigestAlgorithm(), newParamSpec.getDigestAlgorithm()))
            {
                throw new InvalidAlgorithmParameterException("Digest algorithm for MGF should be the same as for PSS parameters.");
            }

            Algorithm newDigest = DigestUtil.getDigestID(mgfParams.getDigestAlgorithm());

            if (newDigest == null)
            {
                throw new InvalidAlgorithmParameterException("No match on MGF digest algorithm: "+ mgfParams.getDigestAlgorithm());
            }

            if (newDigest instanceof FipsAlgorithm)
            {
                parameters = FipsRSA.PSS.withDigestAlgorithm((FipsDigestAlgorithm)newDigest).withMGFDigest((FipsDigestAlgorithm)newDigest).withSaltLength(newParamSpec.getSaltLength()).withTrailer(getPssTrailer(newParamSpec.getTrailerField()));
            }
            else
            {
                throw new InvalidAlgorithmParameterException("Digest algorithm not supported: "+ mgfParams.getDigestAlgorithm());
            }
            this.paramSpec = newParamSpec;
            if (dataStream != null)
            {
                if (key instanceof AsymmetricPrivateKey)
                {
                    signer = Utils.addRandomIfNeeded(operatorFactory.createSigner((AsymmetricPrivateKey)key, parameters), fipsProvider.getDefaultSecureRandom());
                    dataStream = signer.getSigningStream();
                }
                else
                {
                    verifier = operatorFactory.createVerifier((AsymmetricPublicKey)key, parameters);
                    dataStream = verifier.getVerifyingStream();
                }
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Only PSSParameterSpec supported");
        }
    }

    private byte getPssTrailer(
        int trailerField)
    {
        if (trailerField == 1)
        {
            return TRAILER_IMPLICIT;
        }

        throw new IllegalArgumentException("Unknown trailer field");
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (paramSpec != null)
            {
                try
                {
                    engineParams = AlgorithmParameters.getInstance("PSS", fipsProvider);
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new IllegalStateException(e.toString(), e);
                }
            }
        }

        return engineParams;
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a>
     */
    protected void engineSetParameter(
        String  param,
        Object  value)
    {
        throw new UnsupportedOperationException("SetParameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#engineGetParameters()">engineGetParameters()</a>
     */
    protected Object engineGetParameter(
        String      param)
    {
        throw new UnsupportedOperationException("GetParameter unsupported");
    }
}
