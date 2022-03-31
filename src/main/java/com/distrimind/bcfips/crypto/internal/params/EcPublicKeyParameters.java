/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.crypto.internal.params;

import com.distrimind.bcfips.math.ec.ECPoint;

public class EcPublicKeyParameters
    extends EcKeyParameters
{
    ECPoint Q;

    public EcPublicKeyParameters(
        ECPoint             Q,
        EcDomainParameters params)
    {
        super(false, params);

        this.Q = EcDomainParameters.validate(params.getCurve(), Q);
    }

    public ECPoint getQ()
    {
        return Q;
    }
}
