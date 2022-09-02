/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.math.ec.custom.sec;

import java.math.BigInteger;

import com.distrimind.bcfips.math.ec.ECCurve;
import com.distrimind.bcfips.math.ec.ECCurve.AbstractF2m;
import com.distrimind.bcfips.math.ec.ECFieldElement;
import com.distrimind.bcfips.math.ec.ECLookupTable;
import com.distrimind.bcfips.math.ec.ECPoint;
import com.distrimind.bcfips.math.internal.Nat192;
import com.distrimind.bcfips.util.encoders.Hex;

public class SecT131R2Curve extends AbstractF2m
{
    private static final int SecT131R2_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT131R2Point infinity;

    public SecT131R2Curve()
    {
        super(131, 2, 3, 8);

        this.infinity = new SecT131R2Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1, Hex.decode("03E5A88919D7CAFCBF415F07C2176573B2")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decode("04B8266A46C55657AC734CE38F018F2192")));
        this.order = new BigInteger(1, Hex.decode("0400000000000000016954A233049BA98F"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT131R2_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT131R2Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_LAMBDA_PROJECTIVE:
            return true;
        default:
            return false;
        }
    }

    public int getFieldSize()
    {
        return 131;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT131FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecT131R2Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecT131R2Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public boolean isKoblitz()
    {
        return false;
    }

    public int getM()
    {
        return 131;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 3;
    }

    public int getK3()
    {
        return 8;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_LONGS = 3;

        final long[] table = new long[len * FE_LONGS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat192.copy64(((SecT131FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat192.copy64(((SecT131FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
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
                long[] x = Nat192.create64(), y = Nat192.create64();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    long MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_LONGS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_LONGS + j] & MASK;
                    }

                    pos += (FE_LONGS * 2);
                }

                return createRawPoint(new SecT131FieldElement(x), new SecT131FieldElement(y));
            }
        };
    }
}
