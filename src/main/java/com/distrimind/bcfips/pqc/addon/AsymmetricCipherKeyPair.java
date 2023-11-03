package com.distrimind.bcfips.pqc.addon;

/**
 * a holding class for public/private parameter pairs.
 */
class AsymmetricCipherKeyPair
{
    private Object    publicParam;
    private Object    privateParam;

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
     */
    public AsymmetricCipherKeyPair(
        Object    publicParam,
        Object    privateParam)
    {
        this.publicParam = publicParam;
        this.privateParam = privateParam;
    }

    /**
     * return the public key parameters.
     *
     * @return the public key parameters.
     */
    public Object getPublic()
    {
        return publicParam;
    }

    /**
     * return the private key parameters.
     *
     * @return the private key parameters.
     */
    public Object getPrivate()
    {
        return privateParam;
    }
}
