/**
 * Custom, optimized implementations of the SEC curves. These are much faster than the default implementation
 * due to the use of curve-specific optimizations (in particular, fast reduction in the underlying fields) and also
 * the use of fixed-size buffers instead of the (immutable) BigInteger class.
 */
package com.distrimind.bcfips.math.ec.custom.sec;
