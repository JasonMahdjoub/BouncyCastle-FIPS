package com.distrimind.bcfips.crypto.general;

import com.distrimind.bcfips.crypto.*;
import com.distrimind.bcfips.crypto.fips.FipsStatus;
import com.distrimind.bcfips.crypto.fips.FipsUnapprovedOperationError;
import com.distrimind.bcfips.crypto.internal.Mac;
import com.distrimind.bcfips.crypto.internal.io.MacOutputStream;

abstract class GuardedMACOperatorFactory<T extends AuthenticationParameters>
    implements MACOperatorFactory<T>
{
    // package protect constructor
    GuardedMACOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public final OutputMACCalculator<T> createOutputMACCalculator(SymmetricKey key, final T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        final Mac mac = createMAC(key, parameters);

        return new OutputMACCalculator<T>()
        {
            public T getParameters()
            {
                return parameters;
            }

            public int getMACSize()
            {
                return mac.getMacSize();
            }

            public UpdateOutputStream getMACStream()
            {
                return new MacOutputStream(mac);
            }

            public byte[] getMAC()
            {
                byte[] res = new byte[mac.getMacSize()];

                getMAC(res, 0);

                return res;
            }

            public int getMAC(byte[] output, int off)
            {
                return mac.doFinal(output, off);
            }

            public void reset()
            {
                mac.reset();
            }
        };
    }

    protected abstract Mac createMAC(SymmetricKey key, T parameter);

    protected abstract int calculateMACSize(T parameters);
}
