package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.internal.AsymmetricCipherKeyPair;
import com.distrimind.bcfips.crypto.internal.params.EcPrivateKeyParameters;
import com.distrimind.bcfips.crypto.internal.params.EcPublicKeyParameters;

class DSTU4145KeyPairGenerator
    extends EcKeyPairGenerator
{
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = super.generateKeyPair();

        EcPublicKeyParameters pub = (EcPublicKeyParameters)pair.getPublic();
        EcPrivateKeyParameters priv = (EcPrivateKeyParameters)pair.getPrivate();

        pub = new EcPublicKeyParameters(pub.getQ().negate(), pub.getParameters());

        return new AsymmetricCipherKeyPair(pub, priv);
    }
}
