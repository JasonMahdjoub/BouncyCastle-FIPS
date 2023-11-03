package com.distrimind.bcfips.pqc.addon;

class CMCEKeyParameters
    extends AsymmetricKeyParameter
{
    private CMCEParameters params;

    public CMCEKeyParameters(
        boolean isPrivate,
        CMCEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }

}
