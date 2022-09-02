/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.math.ec.custom.sec;

import java.math.BigInteger;

import com.distrimind.bcfips.math.ec.ECConstants;
import com.distrimind.bcfips.math.ec.ECCurve;
import com.distrimind.bcfips.math.ec.ECFieldElement;
import com.distrimind.bcfips.math.ec.ECLookupTable;
import com.distrimind.bcfips.math.ec.ECPoint;
import com.distrimind.bcfips.math.internal.Nat224;
import com.distrimind.bcfips.util.encoders.Hex;

public class SecP224K1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D"));

    private static final int SECP224K1_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP224K1Point infinity;

    public SecP224K1Curve()
    {
        super(q);

        this.infinity = new SecP224K1Point(this, null, null);

        this.a = fromBigInteger(ECConstants.ZERO);
        this.b = fromBigInteger(BigInteger.valueOf(5));
        this.order = new BigInteger(1, Hex.decode("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = SECP224K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP224K1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_JACOBIAN:
            return true;
        default:
            return false;
        }
    }

    public BigInteger getQ()
    {
        return q;
    }

    public int getFieldSize()
    {
        return q.bitLength();
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecP224K1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecP224K1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecP224K1Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_INTS = 7;

        final int[] table = new int[len * FE_INTS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat224.copy(((SecP224K1FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat224.copy(((SecP224K1FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
            }
        }

        return new ECLookupTable()
        {
            public int getSize()
            {
                return len;
            }

            public ECPoint lookup(int index)
            {
                int[] x = Nat224.create(), y = Nat224.create();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    int MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_INTS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_INTS + j] & MASK;
                    }

                    pos += (FE_INTS * 2);
                }

                return createRawPoint(new SecP224K1FieldElement(x), new SecP224K1FieldElement(y));
            }
        };
    }
}
