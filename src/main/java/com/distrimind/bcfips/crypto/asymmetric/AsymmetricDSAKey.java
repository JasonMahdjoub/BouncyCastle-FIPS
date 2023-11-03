package com.distrimind.bcfips.crypto.asymmetric;

import java.util.HashSet;
import java.util.Set;

import com.distrimind.bcfips.asn1.ASN1ObjectIdentifier;
import com.distrimind.bcfips.asn1.oiw.OIWObjectIdentifiers;
import com.distrimind.bcfips.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bcfips.asn1.x509.DSAParameter;
import com.distrimind.bcfips.asn1.x9.X9ObjectIdentifiers;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricKey;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;

/**
 * Base class for Digital Signature Algorithm (DSA) keys.
 */
public abstract class AsymmetricDSAKey
    implements AsymmetricKey
{
    private static final Set<ASN1ObjectIdentifier> dsaOids = new HashSet<ASN1ObjectIdentifier>(3);

    static
    {
        dsaOids.add(X9ObjectIdentifiers.id_dsa);
        dsaOids.add(X9ObjectIdentifiers.id_dsa_with_sha1);
        dsaOids.add(OIWObjectIdentifiers.dsaWithSHA1);
    }

    protected final boolean    approvedModeOnly;

    protected Algorithm algorithm;
    protected DSADomainParameters domainParameters;

    AsymmetricDSAKey(Algorithm algorithm, DSADomainParameters domainParameters)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
    }

    AsymmetricDSAKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier)
    {
        this.approvedModeOnly = CryptoServicesRegistrar.isInApprovedOnlyMode();
        this.algorithm = algorithm;
        this.domainParameters = decodeDomainParameters(algorithmIdentifier);
    }

    private static DSADomainParameters decodeDomainParameters(AlgorithmIdentifier algorithmIdentifier)
    {
        if (!dsaOids.contains(algorithmIdentifier.getAlgorithm()))
        {
            throw new IllegalArgumentException("Unknown algorithm type: " + algorithmIdentifier.getAlgorithm());
        }

        if (KeyUtils.isNotNull(algorithmIdentifier.getParameters()))
        {
            DSAParameter params = DSAParameter.getInstance(algorithmIdentifier.getParameters());

            return new DSADomainParameters(params.getP(), params.getQ(), params.getG());
        }

        return null;
    }

    /**
     * Return the algorithm this DSA key is for.
     *
     * @return the key's algorithm.
     */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the DSA domain parameters associated with this key.
     *
     * @return the DSA domain parameters for this key.
     */
    public DSADomainParameters getDomainParameters()
    {
        return domainParameters;
    }

    protected final void checkApprovedOnlyModeStatus()
    {
        if (approvedModeOnly != CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("No access to key in current thread.");
        }
    }

    protected void zeroize()
    {
        this.algorithm = null;
        this.domainParameters = null;
    }
}
