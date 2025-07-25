var dbits, canary = 0xdeadbeefcafe, j_lm = 15715070 == (canary & 16777215);
function BigInteger(a, b, c) {
    null != a && ("number" == typeof a ? this.fromNumber(a, b, c) : null == b && "string" != typeof a ? this.fromString(a, 256) : this.fromString(a, b))
}
function nbi() {
    return new BigInteger(null)
}
function am1(a, b, c, d, e, f) {
    for (; 0 <= --f;) {
        var g = b * this[a++] + c[d] + e;
        e = Math.floor(g / 67108864);
        c[d++] = g & 67108863
    }
    return e
}
function am2(a, b, c, d, e, f) {
    var g = b & 32767;
    for (b >>= 15; 0 <= --f;) {
        var h = this[a] & 32767
            , n = this[a++] >> 15
            , k = b * h + n * g
            , h = g * h + ((k & 32767) << 15) + c[d] + (e & 1073741823);
        e = (h >>> 30) + (k >>> 15) + b * n + (e >>> 30);
        c[d++] = h & 1073741823
    }
    return e
}
function am3(a, b, c, d, e, f) {
    var g = b & 16383;
    for (b >>= 14; 0 <= --f;) {
        var h = this[a] & 16383
            , n = this[a++] >> 14
            , k = b * h + n * g
            , h = g * h + ((k & 16383) << 14) + c[d] + e;
        e = (h >> 28) + (k >> 14) + b * n;
        c[d++] = h & 268435455
    }
    return e
}
j_lm && "Microsoft Internet Explorer" == navigator.appName ? (BigInteger.prototype.am = am2,
    dbits = 30) : j_lm && "Netscape" != navigator.appName ? (BigInteger.prototype.am = am1,
        dbits = 26) : (BigInteger.prototype.am = am3,
            dbits = 28);
BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = (1 << dbits) - 1;
BigInteger.prototype.DV = 1 << dbits;
var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz", BI_RC = [], rr, vv;
rr = 48;
for (vv = 0; 9 >= vv; ++vv)
    BI_RC[rr++] = vv;
rr = 97;
for (vv = 10; 36 > vv; ++vv)
    BI_RC[rr++] = vv;
rr = 65;
for (vv = 10; 36 > vv; ++vv)
    BI_RC[rr++] = vv;
function int2char(a) {
    return BI_RM.charAt(a)
}
function intAt(a, b) {
    var c = BI_RC[a.charCodeAt(b)];
    return null == c ? -1 : c
}
function bnpCopyTo(a) {
    for (var b = this.t - 1; 0 <= b; --b)
        a[b] = this[b];
    a.t = this.t;
    a.s = this.s
}
function bnpFromInt(a) {
    this.t = 1;
    this.s = 0 > a ? -1 : 0;
    0 < a ? this[0] = a : -1 > a ? this[0] = a + this.DV : this.t = 0
}
function nbv(a) {
    var b = nbi();
    b.fromInt(a);
    return b
}
function bnpFromString(a, b) {
    var c;
    if (16 == b)
        c = 4;
    else if (8 == b)
        c = 3;
    else if (256 == b)
        c = 8;
    else if (2 == b)
        c = 1;
    else if (32 == b)
        c = 5;
    else if (4 == b)
        c = 2;
    else {
        this.fromRadix(a, b);
        return
    }
    this.s = this.t = 0;
    for (var d = a.length, e = !1, f = 0; 0 <= --d;) {
        var g = 8 == c ? a[d] & 255 : intAt(a, d);
        0 > g ? "-" == a.charAt(d) && (e = !0) : (e = !1,
            0 == f ? this[this.t++] = g : f + c > this.DB ? (this[this.t - 1] |= (g & (1 << this.DB - f) - 1) << f,
                this[this.t++] = g >> this.DB - f) : this[this.t - 1] |= g << f,
            f += c,
            f >= this.DB && (f -= this.DB))
    }
    8 == c && 0 != (a[0] & 128) && (this.s = -1,
        0 < f && (this[this.t - 1] |= (1 << this.DB - f) - 1 << f));
    this.clamp();
    e && BigInteger.ZERO.subTo(this, this)
}
function bnpClamp() {
    for (var a = this.s & this.DM; 0 < this.t && this[this.t - 1] == a;)
        --this.t
}
function bnToString(a) {
    if (0 > this.s)
        return "-" + this.negate().toString(a);
    if (16 == a)
        a = 4;
    else if (8 == a)
        a = 3;
    else if (2 == a)
        a = 1;
    else if (32 == a)
        a = 5;
    else if (4 == a)
        a = 2;
    else
        return this.toRadix(a);
    var b = (1 << a) - 1, c, d = !1, e = "", f = this.t, g = this.DB - f * this.DB % a;
    if (0 < f--) {
        if (g < this.DB && 0 < (c = this[f] >> g))
            d = !0,
                e = int2char(c);
        for (; 0 <= f;)
            g < a ? (c = (this[f] & (1 << g) - 1) << a - g,
                c |= this[--f] >> (g += this.DB - a)) : (c = this[f] >> (g -= a) & b,
                    0 >= g && (g += this.DB,
                        --f)),
                0 < c && (d = !0),
                d && (e += int2char(c))
    }
    return d ? e : "0"
}
function bnNegate() {
    var a = nbi();
    BigInteger.ZERO.subTo(this, a);
    return a
}
function bnAbs() {
    return 0 > this.s ? this.negate() : this
}
function bnCompareTo(a) {
    var b = this.s - a.s;
    if (0 != b)
        return b;
    var c = this.t
        , b = c - a.t;
    if (0 != b)
        return 0 > this.s ? -b : b;
    for (; 0 <= --c;)
        if (0 != (b = this[c] - a[c]))
            return b;
    return 0
}
function nbits(a) {
    var b = 1, c;
    if (0 != (c = a >>> 16))
        a = c,
            b += 16;
    if (0 != (c = a >> 8))
        a = c,
            b += 8;
    if (0 != (c = a >> 4))
        a = c,
            b += 4;
    if (0 != (c = a >> 2))
        a = c,
            b += 2;
    0 != a >> 1 && (b += 1);
    return b
}
function bnBitLength() {
    return 0 >= this.t ? 0 : this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM)
}
function bnpDLShiftTo(a, b) {
    var c;
    for (c = this.t - 1; 0 <= c; --c)
        b[c + a] = this[c];
    for (c = a - 1; 0 <= c; --c)
        b[c] = 0;
    b.t = this.t + a;
    b.s = this.s
}
function bnpDRShiftTo(a, b) {
    for (var c = a; c < this.t; ++c)
        b[c - a] = this[c];
    b.t = Math.max(this.t - a, 0);
    b.s = this.s
}
function bnpLShiftTo(a, b) {
    var c = a % this.DB, d = this.DB - c, e = (1 << d) - 1, f = Math.floor(a / this.DB), g = this.s << c & this.DM, h;
    for (h = this.t - 1; 0 <= h; --h)
        b[h + f + 1] = this[h] >> d | g,
            g = (this[h] & e) << c;
    for (h = f - 1; 0 <= h; --h)
        b[h] = 0;
    b[f] = g;
    b.t = this.t + f + 1;
    b.s = this.s;
    b.clamp()
}
function bnpRShiftTo(a, b) {
    b.s = this.s;
    var c = Math.floor(a / this.DB);
    if (c >= this.t)
        b.t = 0;
    else {
        var d = a % this.DB
            , e = this.DB - d
            , f = (1 << d) - 1;
        b[0] = this[c] >> d;
        for (var g = c + 1; g < this.t; ++g)
            b[g - c - 1] |= (this[g] & f) << e,
                b[g - c] = this[g] >> d;
        0 < d && (b[this.t - c - 1] |= (this.s & f) << e);
        b.t = this.t - c;
        b.clamp()
    }
}
function bnpSubTo(a, b) {
    for (var c = 0, d = 0, e = Math.min(a.t, this.t); c < e;)
        d += this[c] - a[c],
            b[c++] = d & this.DM,
            d >>= this.DB;
    if (a.t < this.t) {
        for (d -= a.s; c < this.t;)
            d += this[c],
                b[c++] = d & this.DM,
                d >>= this.DB;
        d += this.s
    } else {
        for (d += this.s; c < a.t;)
            d -= a[c],
                b[c++] = d & this.DM,
                d >>= this.DB;
        d -= a.s
    }
    b.s = 0 > d ? -1 : 0;
    -1 > d ? b[c++] = this.DV + d : 0 < d && (b[c++] = d);
    b.t = c;
    b.clamp()
}
function bnpMultiplyTo(a, b) {
    var c = this.abs()
        , d = a.abs()
        , e = c.t;
    for (b.t = e + d.t; 0 <= --e;)
        b[e] = 0;
    for (e = 0; e < d.t; ++e)
        b[e + c.t] = c.am(0, d[e], b, e, 0, c.t);
    b.s = 0;
    b.clamp();
    this.s != a.s && BigInteger.ZERO.subTo(b, b)
}
function bnpSquareTo(a) {
    for (var b = this.abs(), c = a.t = 2 * b.t; 0 <= --c;)
        a[c] = 0;
    for (c = 0; c < b.t - 1; ++c) {
        var d = b.am(c, b[c], a, 2 * c, 0, 1);
        if ((a[c + b.t] += b.am(c + 1, 2 * b[c], a, 2 * c + 1, d, b.t - c - 1)) >= b.DV)
            a[c + b.t] -= b.DV,
                a[c + b.t + 1] = 1
    }
    0 < a.t && (a[a.t - 1] += b.am(c, b[c], a, 2 * c, 0, 1));
    a.s = 0;
    a.clamp()
}
function bnpDivRemTo(a, b, c) {
    var d = a.abs();
    if (!(0 >= d.t)) {
        var e = this.abs();
        if (e.t < d.t)
            null != b && b.fromInt(0),
                null != c && this.copyTo(c);
        else {
            null == c && (c = nbi());
            var f = nbi()
                , g = this.s;
            a = a.s;
            var h = this.DB - nbits(d[d.t - 1]);
            0 < h ? (d.lShiftTo(h, f),
                e.lShiftTo(h, c)) : (d.copyTo(f),
                    e.copyTo(c));
            d = f.t;
            e = f[d - 1];
            if (0 != e) {
                var n = e * (1 << this.F1) + (1 < d ? f[d - 2] >> this.F2 : 0)
                    , k = this.FV / n
                    , n = (1 << this.F1) / n
                    , q = 1 << this.F2
                    , r = c.t
                    , C = r - d
                    , u = null == b ? nbi() : b;
                f.dlShiftTo(C, u);
                0 <= c.compareTo(u) && (c[c.t++] = 1,
                    c.subTo(u, c));
                BigInteger.ONE.dlShiftTo(d, u);
                for (u.subTo(f, f); f.t < d;)
                    f[f.t++] = 0;
                for (; 0 <= --C;) {
                    var w = c[--r] == e ? this.DM : Math.floor(c[r] * k + (c[r - 1] + q) * n);
                    if ((c[r] += f.am(0, w, c, C, 0, d)) < w) {
                        f.dlShiftTo(C, u);
                        for (c.subTo(u, c); c[r] < --w;)
                            c.subTo(u, c)
                    }
                }
                null != b && (c.drShiftTo(d, b),
                    g != a && BigInteger.ZERO.subTo(b, b));
                c.t = d;
                c.clamp();
                0 < h && c.rShiftTo(h, c);
                0 > g && BigInteger.ZERO.subTo(c, c)
            }
        }
    }
}
function bnMod(a) {
    var b = nbi();
    this.abs().divRemTo(a, null, b);
    0 > this.s && 0 < b.compareTo(BigInteger.ZERO) && a.subTo(b, b);
    return b
}
function Classic(a) {
    this.m = a
}
function cConvert(a) {
    return 0 > a.s || 0 <= a.compareTo(this.m) ? a.mod(this.m) : a
}
function cRevert(a) {
    return a
}
function cReduce(a) {
    a.divRemTo(this.m, null, a)
}
function cMulTo(a, b, c) {
    a.multiplyTo(b, c);
    this.reduce(c)
}
function cSqrTo(a, b) {
    a.squareTo(b);
    this.reduce(b)
}
Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;
function bnpInvDigit() {
    if (1 > this.t)
        return 0;
    var a = this[0];
    if (0 == (a & 1))
        return 0;
    var b = a & 3
        , b = b * (2 - (a & 15) * b) & 15
        , b = b * (2 - (a & 255) * b) & 255
        , b = b * (2 - ((a & 65535) * b & 65535)) & 65535
        , b = b * (2 - a * b % this.DV) % this.DV;
    return 0 < b ? this.DV - b : -b
}
function Montgomery(a) {
    this.m = a;
    this.mp = a.invDigit();
    this.mpl = this.mp & 32767;
    this.mph = this.mp >> 15;
    this.um = (1 << a.DB - 15) - 1;
    this.mt2 = 2 * a.t
}
function montConvert(a) {
    var b = nbi();
    a.abs().dlShiftTo(this.m.t, b);
    b.divRemTo(this.m, null, b);
    0 > a.s && 0 < b.compareTo(BigInteger.ZERO) && this.m.subTo(b, b);
    return b
}
function montRevert(a) {
    var b = nbi();
    a.copyTo(b);
    this.reduce(b);
    return b
}
function montReduce(a) {
    for (; a.t <= this.mt2;)
        a[a.t++] = 0;
    for (var b = 0; b < this.m.t; ++b) {
        var c = a[b] & 32767
            , d = c * this.mpl + ((c * this.mph + (a[b] >> 15) * this.mpl & this.um) << 15) & a.DM
            , c = b + this.m.t;
        for (a[c] += this.m.am(0, d, a, b, 0, this.m.t); a[c] >= a.DV;)
            a[c] -= a.DV,
                a[++c]++
    }
    a.clamp();
    a.drShiftTo(this.m.t, a);
    0 <= a.compareTo(this.m) && a.subTo(this.m, a)
}
function montSqrTo(a, b) {
    a.squareTo(b);
    this.reduce(b)
}
function montMulTo(a, b, c) {
    a.multiplyTo(b, c);
    this.reduce(c)
}
Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;
function bnpIsEven() {
    return 0 == (0 < this.t ? this[0] & 1 : this.s)
}
function bnpExp(a, b) {
    if (4294967295 < a || 1 > a)
        return BigInteger.ONE;
    var c = nbi()
        , d = nbi()
        , e = b.convert(this)
        , f = nbits(a) - 1;
    for (e.copyTo(c); 0 <= --f;)
        if (b.sqrTo(c, d),
            0 < (a & 1 << f))
            b.mulTo(d, e, c);
        else
            var g = c
                , c = d
                , d = g;
    return b.revert(c)
}
function bnModPowInt(a, b) {
    var c;
    c = 256 > a || b.isEven() ? new Classic(b) : new Montgomery(b);
    return this.exp(a, c)
}
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
function bnClone() {
    var a = nbi();
    this.copyTo(a);
    return a
}
function bnIntValue() {
    if (0 > this.s) {
        if (1 == this.t)
            return this[0] - this.DV;
        if (0 == this.t)
            return -1
    } else {
        if (1 == this.t)
            return this[0];
        if (0 == this.t)
            return 0
    }
    return (this[1] & (1 << 32 - this.DB) - 1) << this.DB | this[0]
}
function bnByteValue() {
    return 0 == this.t ? this.s : this[0] << 24 >> 24
}
function bnShortValue() {
    return 0 == this.t ? this.s : this[0] << 16 >> 16
}
function bnpChunkSize(a) {
    return Math.floor(Math.LN2 * this.DB / Math.log(a))
}
function bnSigNum() {
    return 0 > this.s ? -1 : 0 >= this.t || 1 == this.t && 0 >= this[0] ? 0 : 1
}
function bnpToRadix(a) {
    null == a && (a = 10);
    if (0 == this.signum() || 2 > a || 36 < a)
        return "0";
    var b = this.chunkSize(a)
        , b = Math.pow(a, b)
        , c = nbv(b)
        , d = nbi()
        , e = nbi()
        , f = "";
    for (this.divRemTo(c, d, e); 0 < d.signum();)
        f = (b + e.intValue()).toString(a).substr(1) + f,
            d.divRemTo(c, d, e);
    return e.intValue().toString(a) + f
}
function bnpFromRadix(a, b) {
    this.fromInt(0);
    null == b && (b = 10);
    for (var c = this.chunkSize(b), d = Math.pow(b, c), e = !1, f = 0, g = 0, h = 0; h < a.length; ++h) {
        var n = intAt(a, h);
        0 > n ? "-" == a.charAt(h) && 0 == this.signum() && (e = !0) : (g = b * g + n,
            ++f >= c && (this.dMultiply(d),
                this.dAddOffset(g, 0),
                g = f = 0))
    }
    0 < f && (this.dMultiply(Math.pow(b, f)),
        this.dAddOffset(g, 0));
    e && BigInteger.ZERO.subTo(this, this)
}
function bnpFromNumber(a, b, c) {
    if ("number" == typeof b)
        if (2 > a)
            this.fromInt(1);
        else {
            this.fromNumber(a, c);
            this.testBit(a - 1) || this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
            for (this.isEven() && this.dAddOffset(1, 0); !this.isProbablePrime(b);)
                this.dAddOffset(2, 0),
                    this.bitLength() > a && this.subTo(BigInteger.ONE.shiftLeft(a - 1), this)
        }
    else {
        c = [];
        var d = a & 7;
        c.length = (a >> 3) + 1;
        b.nextBytes(c);
        c[0] = 0 < d ? c[0] & (1 << d) - 1 : 0;
        this.fromString(c, 256)
    }
}
function bnToByteArray() {
    var a = this.t
        , b = [];
    b[0] = this.s;
    var c = this.DB - a * this.DB % 8, d, e = 0;
    if (0 < a--) {
        if (c < this.DB && (d = this[a] >> c) != (this.s & this.DM) >> c)
            b[e++] = d | this.s << this.DB - c;
        for (; 0 <= a;)
            if (8 > c ? (d = (this[a] & (1 << c) - 1) << 8 - c,
                d |= this[--a] >> (c += this.DB - 8)) : (d = this[a] >> (c -= 8) & 255,
                    0 >= c && (c += this.DB,
                        --a)),
                0 != (d & 128) && (d |= -256),
                0 == e && (this.s & 128) != (d & 128) && ++e,
                0 < e || d != this.s)
                b[e++] = d
    }
    return b
}
function bnEquals(a) {
    return 0 == this.compareTo(a)
}
function bnMin(a) {
    return 0 > this.compareTo(a) ? this : a
}
function bnMax(a) {
    return 0 < this.compareTo(a) ? this : a
}
function bnpBitwiseTo(a, b, c) {
    var d, e, f = Math.min(a.t, this.t);
    for (d = 0; d < f; ++d)
        c[d] = b(this[d], a[d]);
    if (a.t < this.t) {
        e = a.s & this.DM;
        for (d = f; d < this.t; ++d)
            c[d] = b(this[d], e);
        c.t = this.t
    } else {
        e = this.s & this.DM;
        for (d = f; d < a.t; ++d)
            c[d] = b(e, a[d]);
        c.t = a.t
    }
    c.s = b(this.s, a.s);
    c.clamp()
}
function op_and(a, b) {
    return a & b
}
function bnAnd(a) {
    var b = nbi();
    this.bitwiseTo(a, op_and, b);
    return b
}
function op_or(a, b) {
    return a | b
}
function bnOr(a) {
    var b = nbi();
    this.bitwiseTo(a, op_or, b);
    return b
}
function op_xor(a, b) {
    return a ^ b
}
function bnXor(a) {
    var b = nbi();
    this.bitwiseTo(a, op_xor, b);
    return b
}
function op_andnot(a, b) {
    return a & ~b
}
function bnAndNot(a) {
    var b = nbi();
    this.bitwiseTo(a, op_andnot, b);
    return b
}
function bnNot() {
    for (var a = nbi(), b = 0; b < this.t; ++b)
        a[b] = this.DM & ~this[b];
    a.t = this.t;
    a.s = ~this.s;
    return a
}
function bnShiftLeft(a) {
    var b = nbi();
    0 > a ? this.rShiftTo(-a, b) : this.lShiftTo(a, b);
    return b
}
function bnShiftRight(a) {
    var b = nbi();
    0 > a ? this.lShiftTo(-a, b) : this.rShiftTo(a, b);
    return b
}
function lbit(a) {
    if (0 == a)
        return -1;
    var b = 0;
    0 == (a & 65535) && (a >>= 16,
        b += 16);
    0 == (a & 255) && (a >>= 8,
        b += 8);
    0 == (a & 15) && (a >>= 4,
        b += 4);
    0 == (a & 3) && (a >>= 2,
        b += 2);
    0 == (a & 1) && ++b;
    return b
}
function bnGetLowestSetBit() {
    for (var a = 0; a < this.t; ++a)
        if (0 != this[a])
            return a * this.DB + lbit(this[a]);
    return 0 > this.s ? this.t * this.DB : -1
}
function cbit(a) {
    for (var b = 0; 0 != a;)
        a &= a - 1,
            ++b;
    return b
}
function bnBitCount() {
    for (var a = 0, b = this.s & this.DM, c = 0; c < this.t; ++c)
        a += cbit(this[c] ^ b);
    return a
}
function bnTestBit(a) {
    var b = Math.floor(a / this.DB);
    return b >= this.t ? 0 != this.s : 0 != (this[b] & 1 << a % this.DB)
}
function bnpChangeBit(a, b) {
    var c = BigInteger.ONE.shiftLeft(a);
    this.bitwiseTo(c, b, c);
    return c
}
function bnSetBit(a) {
    return this.changeBit(a, op_or)
}
function bnClearBit(a) {
    return this.changeBit(a, op_andnot)
}
function bnFlipBit(a) {
    return this.changeBit(a, op_xor)
}
function bnpAddTo(a, b) {
    for (var c = 0, d = 0, e = Math.min(a.t, this.t); c < e;)
        d += this[c] + a[c],
            b[c++] = d & this.DM,
            d >>= this.DB;
    if (a.t < this.t) {
        for (d += a.s; c < this.t;)
            d += this[c],
                b[c++] = d & this.DM,
                d >>= this.DB;
        d += this.s
    } else {
        for (d += this.s; c < a.t;)
            d += a[c],
                b[c++] = d & this.DM,
                d >>= this.DB;
        d += a.s
    }
    b.s = 0 > d ? -1 : 0;
    0 < d ? b[c++] = d : -1 > d && (b[c++] = this.DV + d);
    b.t = c;
    b.clamp()
}
function bnAdd(a) {
    var b = nbi();
    this.addTo(a, b);
    return b
}
function bnSubtract(a) {
    var b = nbi();
    this.subTo(a, b);
    return b
}
function bnMultiply(a) {
    var b = nbi();
    this.multiplyTo(a, b);
    return b
}
function bnSquare() {
    var a = nbi();
    this.squareTo(a);
    return a
}
function bnDivide(a) {
    var b = nbi();
    this.divRemTo(a, b, null);
    return b
}
function bnRemainder(a) {
    var b = nbi();
    this.divRemTo(a, null, b);
    return b
}
function bnDivideAndRemainder(a) {
    var b = nbi()
        , c = nbi();
    this.divRemTo(a, b, c);
    return [b, c]
}
function bnpDMultiply(a) {
    this[this.t] = this.am(0, a - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp()
}
function bnpDAddOffset(a, b) {
    if (0 != a) {
        for (; this.t <= b;)
            this[this.t++] = 0;
        for (this[b] += a; this[b] >= this.DV;)
            this[b] -= this.DV,
                ++b >= this.t && (this[this.t++] = 0),
                ++this[b]
    }
}
function NullExp() { }
function nNop(a) {
    return a
}
function nMulTo(a, b, c) {
    a.multiplyTo(b, c)
}
function nSqrTo(a, b) {
    a.squareTo(b)
}
NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;
function bnPow(a) {
    return this.exp(a, new NullExp)
}
function bnpMultiplyLowerTo(a, b, c) {
    var d = Math.min(this.t + a.t, b);
    c.s = 0;
    for (c.t = d; 0 < d;)
        c[--d] = 0;
    var e;
    for (e = c.t - this.t; d < e; ++d)
        c[d + this.t] = this.am(0, a[d], c, d, 0, this.t);
    for (e = Math.min(a.t, b); d < e; ++d)
        this.am(0, a[d], c, d, 0, b - d);
    c.clamp()
}
function bnpMultiplyUpperTo(a, b, c) {
    --b;
    var d = c.t = this.t + a.t - b;
    for (c.s = 0; 0 <= --d;)
        c[d] = 0;
    for (d = Math.max(b - this.t, 0); d < a.t; ++d)
        c[this.t + d - b] = this.am(b - d, a[d], c, 0, 0, this.t + d - b);
    c.clamp();
    c.drShiftTo(1, c)
}
function Barrett(a) {
    this.r2 = nbi();
    this.q3 = nbi();
    BigInteger.ONE.dlShiftTo(2 * a.t, this.r2);
    this.mu = this.r2.divide(a);
    this.m = a
}
function barrettConvert(a) {
    if (0 > a.s || a.t > 2 * this.m.t)
        return a.mod(this.m);
    if (0 > a.compareTo(this.m))
        return a;
    var b = nbi();
    a.copyTo(b);
    this.reduce(b);
    return b
}
function barrettRevert(a) {
    return a
}
function barrettReduce(a) {
    a.drShiftTo(this.m.t - 1, this.r2);
    a.t > this.m.t + 1 && (a.t = this.m.t + 1,
        a.clamp());
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    for (this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2); 0 > a.compareTo(this.r2);)
        a.dAddOffset(1, this.m.t + 1);
    for (a.subTo(this.r2, a); 0 <= a.compareTo(this.m);)
        a.subTo(this.m, a)
}
function barrettSqrTo(a, b) {
    a.squareTo(b);
    this.reduce(b)
}
function barrettMulTo(a, b, c) {
    a.multiplyTo(b, c);
    this.reduce(c)
}
Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;
function bnModPow(a, b) {
    var c = a.bitLength(), d, e = nbv(1), f;
    if (0 >= c)
        return e;
    d = 18 > c ? 1 : 48 > c ? 3 : 144 > c ? 4 : 768 > c ? 5 : 6;
    f = 8 > c ? new Classic(b) : b.isEven() ? new Barrett(b) : new Montgomery(b);
    var g = []
        , h = 3
        , n = d - 1
        , k = (1 << d) - 1;
    g[1] = f.convert(this);
    if (1 < d) {
        c = nbi();
        for (f.sqrTo(g[1], c); h <= k;)
            g[h] = nbi(),
                f.mulTo(c, g[h - 2], g[h]),
                h += 2
    }
    for (var q = a.t - 1, r, C = !0, u = nbi(), c = nbits(a[q]) - 1; 0 <= q;) {
        c >= n ? r = a[q] >> c - n & k : (r = (a[q] & (1 << c + 1) - 1) << n - c,
            0 < q && (r |= a[q - 1] >> this.DB + c - n));
        for (h = d; 0 == (r & 1);)
            r >>= 1,
                --h;
        if (0 > (c -= h))
            c += this.DB,
                --q;
        if (C)
            g[r].copyTo(e),
                C = !1;
        else {
            for (; 1 < h;)
                f.sqrTo(e, u),
                    f.sqrTo(u, e),
                    h -= 2;
            0 < h ? f.sqrTo(e, u) : (h = e,
                e = u,
                u = h);
            f.mulTo(u, g[r], e)
        }
        for (; 0 <= q && 0 == (a[q] & 1 << c);)
            f.sqrTo(e, u),
                h = e,
                e = u,
                u = h,
                0 > --c && (c = this.DB - 1,
                    --q)
    }
    return f.revert(e)
}
(function () {
    var a = []
        , b = window.postMessage && window.addEventListener;
    b && window.addEventListener("message", function (b) {
        b.source == window && "zero-timeout-message" == b.data && (b.stopPropagation(),
            0 < a.length && a.shift()())
    }, !0);
    window.setZeroTimeout = function (c) {
        b ? (a.push(c),
            window.postMessage("zero-timeout-message", "*")) : window.setTimeout(c, 1)
    }
}
)();
function bnModPowPromise(a, b) {
    function c() {
        if (0 <= u) {
            e >= q ? w = a[u] >> e - q & r : (w = (a[u] & (1 << e + 1) - 1) << q - e,
                0 < u && (w |= a[u - 1] >> this.DB + e - q));
            for (k = f; 0 == (w & 1);)
                w >>= 1,
                    --k;
            if (0 > (e -= k))
                e += this.DB,
                    --u;
            if (F)
                n[w].copyTo(g),
                    F = !1;
            else {
                for (; 1 < k;)
                    h.sqrTo(g, D),
                        h.sqrTo(D, g),
                        k -= 2;
                0 < k ? h.sqrTo(g, D) : (x = g,
                    g = D,
                    D = x);
                h.mulTo(D, n[w], g)
            }
            for (; 0 <= u && 0 == (a[u] & 1 << e);)
                h.sqrTo(g, D),
                    x = g,
                    g = D,
                    D = x,
                    0 > --e && (e = this.DB - 1,
                        --u);
            window.setZeroTimeout(d)
        } else
            B.resolve(h.revert(g))
    }
    function d() {
        c.call(y)
    }
    var e = a.bitLength(), f, g = nbv(1), h;
    if (0 >= e)
        return g;
    f = 18 > e ? 1 : 48 > e ? 3 : 144 > e ? 4 : 768 > e ? 5 : 6;
    h = 8 > e ? new Classic(b) : b.isEven() ? new Barrett(b) : new Montgomery(b);
    var n = []
        , k = 3
        , q = f - 1
        , r = (1 << f) - 1;
    n[1] = h.convert(this);
    if (1 < f) {
        var C = nbi();
        for (h.sqrTo(n[1], C); k <= r;)
            n[k] = nbi(),
                h.mulTo(C, n[k - 2], n[k]),
                k += 2
    }
    var u = a.t - 1, w, F = !0, D = nbi(), x, e = nbits(a[u]) - 1, B = $.Deferred(), y = this;
    window.setZeroTimeout(d);
    return B.promise()
}
function bnGCD(a) {
    var b = 0 > this.s ? this.negate() : this.clone();
    a = 0 > a.s ? a.negate() : a.clone();
    if (0 > b.compareTo(a)) {
        var c = b
            , b = a;
        a = c
    }
    var c = b.getLowestSetBit()
        , d = a.getLowestSetBit();
    if (0 > d)
        return b;
    c < d && (d = c);
    0 < d && (b.rShiftTo(d, b),
        a.rShiftTo(d, a));
    for (; 0 < b.signum();)
        0 < (c = b.getLowestSetBit()) && b.rShiftTo(c, b),
            0 < (c = a.getLowestSetBit()) && a.rShiftTo(c, a),
            0 <= b.compareTo(a) ? (b.subTo(a, b),
                b.rShiftTo(1, b)) : (a.subTo(b, a),
                    a.rShiftTo(1, a));
    0 < d && a.lShiftTo(d, a);
    return a
}
function bnpModInt(a) {
    if (0 >= a)
        return 0;
    var b = this.DV % a
        , c = 0 > this.s ? a - 1 : 0;
    if (0 < this.t)
        if (0 == b)
            c = this[0] % a;
        else
            for (var d = this.t - 1; 0 <= d; --d)
                c = (b * c + this[d]) % a;
    return c
}
function bnModInverse(a) {
    var b = a.isEven();
    if (this.isEven() && b || 0 == a.signum())
        return BigInteger.ZERO;
    for (var c = a.clone(), d = this.clone(), e = nbv(1), f = nbv(0), g = nbv(0), h = nbv(1); 0 != c.signum();) {
        for (; c.isEven();) {
            c.rShiftTo(1, c);
            if (b) {
                if (!e.isEven() || !f.isEven())
                    e.addTo(this, e),
                        f.subTo(a, f);
                e.rShiftTo(1, e)
            } else
                f.isEven() || f.subTo(a, f);
            f.rShiftTo(1, f)
        }
        for (; d.isEven();) {
            d.rShiftTo(1, d);
            if (b) {
                if (!g.isEven() || !h.isEven())
                    g.addTo(this, g),
                        h.subTo(a, h);
                g.rShiftTo(1, g)
            } else
                h.isEven() || h.subTo(a, h);
            h.rShiftTo(1, h)
        }
        0 <= c.compareTo(d) ? (c.subTo(d, c),
            b && e.subTo(g, e),
            f.subTo(h, f)) : (d.subTo(c, d),
                b && g.subTo(e, g),
                h.subTo(f, h))
    }
    if (0 != d.compareTo(BigInteger.ONE))
        return BigInteger.ZERO;
    if (0 <= h.compareTo(a))
        return h.subtract(a);
    if (0 > h.signum())
        h.addTo(a, h);
    else
        return h;
    return 0 > h.signum() ? h.add(a) : h
}
var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    , lplim = 67108864 / lowprimes[lowprimes.length - 1];
function bnIsProbablePrime(a) {
    var b, c = this.abs();
    if (1 == c.t && c[0] <= lowprimes[lowprimes.length - 1]) {
        for (b = 0; b < lowprimes.length; ++b)
            if (c[0] == lowprimes[b])
                return !0;
        return !1
    }
    if (c.isEven())
        return !1;
    for (b = 1; b < lowprimes.length;) {
        for (var d = lowprimes[b], e = b + 1; e < lowprimes.length && d < lplim;)
            d *= lowprimes[e++];
        for (d = c.modInt(d); b < e;)
            if (0 == d % lowprimes[b++])
                return !1
    }
    return c.millerRabin(a)
}
function bnpMillerRabin(a) {
    var b = this.subtract(BigInteger.ONE)
        , c = b.getLowestSetBit();
    if (0 >= c)
        return !1;
    var d = b.shiftRight(c);
    a = a + 1 >> 1;
    a > lowprimes.length && (a = lowprimes.length);
    for (var e = nbi(), f = 0; f < a; ++f) {
        e.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
        var g = e.modPow(d, this);
        if (0 != g.compareTo(BigInteger.ONE) && 0 != g.compareTo(b)) {
            for (var h = 1; h++ < c && 0 != g.compareTo(b);)
                if (g = g.modPowInt(2, this),
                    0 == g.compareTo(BigInteger.ONE))
                    return !1;
            if (0 != g.compareTo(b))
                return !1
        }
    }
    return !0
}
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modPowPromise = bnModPowPromise;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
BigInteger.prototype.square = bnSquare;
function Arcfour() {
    this.j = this.i = 0;
    this.S = []
}
function ARC4init(a) {
    var b, c, d;
    for (b = 0; 256 > b; ++b)
        this.S[b] = b;
    for (b = c = 0; 256 > b; ++b)
        c = c + this.S[b] + a[b % a.length] & 255,
            d = this.S[b],
            this.S[b] = this.S[c],
            this.S[c] = d;
    this.j = this.i = 0
}
function ARC4next() {
    var a;
    this.i = this.i + 1 & 255;
    this.j = this.j + this.S[this.i] & 255;
    a = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = a;
    return this.S[a + this.S[this.i] & 255]
}
Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;
function prng_newstate() {
    return new Arcfour
}
var rng_psize = 256, rng_state, rng_pool, rng_pptr;
function rng_seed_int(a) {
    rng_pool[rng_pptr++] ^= a & 255;
    rng_pool[rng_pptr++] ^= a >> 8 & 255;
    rng_pool[rng_pptr++] ^= a >> 16 & 255;
    rng_pool[rng_pptr++] ^= a >> 24 & 255;
    rng_pptr >= rng_psize && (rng_pptr -= rng_psize)
}
function rng_seed_time() {
    rng_seed_int((new Date).getTime())
}
if (null == rng_pool) {
    rng_pool = [];
    rng_pptr = 0;
    var t;
    if (window.crypto && window.crypto.getRandomValues) {
        var ua = new Uint8Array(32);
        window.crypto.getRandomValues(ua);
        for (t = 0; 32 > t; ++t)
            rng_pool[rng_pptr++] = ua[t]
    }
    if ("Netscape" == navigator.appName && "5" > navigator.appVersion && window.crypto) {
        var z = window.crypto.random(32);
        for (t = 0; t < z.length; ++t)
            rng_pool[rng_pptr++] = z.charCodeAt(t) & 255
    }
    for (; rng_pptr < rng_psize;)
        t = Math.floor(65536 * Math.random()),
            rng_pool[rng_pptr++] = t >>> 8,
            rng_pool[rng_pptr++] = t & 255;
    rng_pptr = 0;
    rng_seed_time()
}
function rng_get_byte() {
    if (null == rng_state) {
        rng_seed_time();
        rng_state = prng_newstate();
        rng_state.init(rng_pool);
        for (rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
            rng_pool[rng_pptr] = 0;
        rng_pptr = 0
    }
    return rng_state.next()
}
function rng_get_bytes(a) {
    var b;
    for (b = 0; b < a.length; ++b)
        a[b] = rng_get_byte()
}
function SecureRandom() { }
SecureRandom.prototype.nextBytes = rng_get_bytes;
(function () {
    function a(a) {
        throw a;
    }
    function b(a, b) {
        this.a = a;
        this.b = b
    }
    function c(a, b) {
        var c = [], d = (1 << b) - 1, e = a.length * b, f;
        for (f = 0; f < e; f += b)
            c[f >>> 5] |= (a.charCodeAt(f / b) & d) << 32 - b - f % 32;
        return {
            value: c,
            binLen: e
        }
    }
    function d(b) {
        var c = [], d = b.length, e, f;
        0 !== d % 2 && a("String of HEX type must be in byte increments");
        for (e = 0; e < d; e += 2)
            f = parseInt(b.substr(e, 2), 16),
                isNaN(f) && a("String of HEX type contains invalid characters"),
                c[e >>> 3] |= f << 24 - 4 * (e % 8);
        return {
            value: c,
            binLen: 4 * d
        }
    }
    function e(b) {
        var c = [], d = 0, e, f, g, h, k;
        -1 === b.search(/^[a-zA-Z0-9=+\/]+$/) && a("Invalid character in base-64 string");
        e = b.indexOf("\x3d");
        b = b.replace(/\=/g, "");
        -1 !== e && e < b.length && a("Invalid '\x3d' found in base-64 string");
        for (f = 0; f < b.length; f += 4) {
            k = b.substr(f, 4);
            for (g = h = 0; g < k.length; g += 1)
                e = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(k[g]),
                    h |= e << 18 - 6 * g;
            for (g = 0; g < k.length - 1; g += 1)
                c[d >> 2] |= (h >>> 16 - 8 * g & 255) << 24 - 8 * (d % 4),
                    d += 1
        }
        return {
            value: c,
            binLen: 8 * d
        }
    }
    function f(a, b) {
        var c = "", d = 4 * a.length, e, f;
        for (e = 0; e < d; e += 1)
            f = a[e >>> 2] >>> 8 * (3 - e % 4),
                c += "0123456789abcdef".charAt(f >>> 4 & 15) + "0123456789abcdef".charAt(f & 15);
        return b.outputUpper ? c.toUpperCase() : c
    }
    function g(a, b) {
        var c = "", d = 4 * a.length, e, f, g;
        for (e = 0; e < d; e += 3) {
            g = (a[e >>> 2] >>> 8 * (3 - e % 4) & 255) << 16 | (a[e + 1 >>> 2] >>> 8 * (3 - (e + 1) % 4) & 255) << 8 | a[e + 2 >>> 2] >>> 8 * (3 - (e + 2) % 4) & 255;
            for (f = 0; 4 > f; f += 1)
                c = 8 * e + 6 * f <= 32 * a.length ? c + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(g >>> 6 * (3 - f) & 63) : c + b.b64Pad
        }
        return c
    }
    function h(b) {
        var c = {
            outputUpper: !1,
            b64Pad: "\x3d"
        };
        try {
            b.hasOwnProperty("outputUpper") && (c.outputUpper = b.outputUpper),
                b.hasOwnProperty("b64Pad") && (c.b64Pad = b.b64Pad)
        } catch (d) { }
        "boolean" !== typeof c.outputUpper && a("Invalid outputUpper formatting option");
        "string" !== typeof c.b64Pad && a("Invalid b64Pad formatting option");
        return c
    }
    function n(a, b) {
        return a >>> b | a << 32 - b
    }
    function k(a, c) {
        return 32 >= c ? new b(a.a >>> c | a.b << 32 - c & 4294967295, a.b >>> c | a.a << 32 - c & 4294967295) : new b(a.b >>> c - 32 | a.a << 64 - c & 4294967295, a.a >>> c - 32 | a.b << 64 - c & 4294967295)
    }
    function q(a, c) {
        return 32 >= c ? new b(a.a >>> c, a.b >>> c | a.a << 32 - c & 4294967295) : new b(0, a.a >>> c - 32)
    }
    function r(a, b, c) {
        return a & b ^ ~a & c
    }
    function C(a, c, d) {
        return new b(a.a & c.a ^ ~a.a & d.a, a.b & c.b ^ ~a.b & d.b)
    }
    function u(a, b, c) {
        return a & b ^ a & c ^ b & c
    }
    function w(a, c, d) {
        return new b(a.a & c.a ^ a.a & d.a ^ c.a & d.a, a.b & c.b ^ a.b & d.b ^ c.b & d.b)
    }
    function F(a) {
        return n(a, 2) ^ n(a, 13) ^ n(a, 22)
    }
    function D(a) {
        var c = k(a, 28)
            , d = k(a, 34);
        a = k(a, 39);
        return new b(c.a ^ d.a ^ a.a, c.b ^ d.b ^ a.b)
    }
    function x(a) {
        return n(a, 6) ^ n(a, 11) ^ n(a, 25)
    }
    function B(a) {
        var c = k(a, 14)
            , d = k(a, 18);
        a = k(a, 41);
        return new b(c.a ^ d.a ^ a.a, c.b ^ d.b ^ a.b)
    }
    function y(a) {
        return n(a, 7) ^ n(a, 18) ^ a >>> 3
    }
    function v(a) {
        var c = k(a, 1)
            , d = k(a, 8);
        a = q(a, 7);
        return new b(c.a ^ d.a ^ a.a, c.b ^ d.b ^ a.b)
    }
    function A(a) {
        return n(a, 17) ^ n(a, 19) ^ a >>> 10
    }
    function p(a) {
        var c = k(a, 19)
            , d = k(a, 61);
        a = q(a, 6);
        return new b(c.a ^ d.a ^ a.a, c.b ^ d.b ^ a.b)
    }
    function K(a, b) {
        var c = (a & 65535) + (b & 65535);
        return ((a >>> 16) + (b >>> 16) + (c >>> 16) & 65535) << 16 | c & 65535
    }
    function N(a, b, c, d) {
        var e = (a & 65535) + (b & 65535) + (c & 65535) + (d & 65535);
        return ((a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) & 65535) << 16 | e & 65535
    }
    function L(a, b, c, d, e) {
        var f = (a & 65535) + (b & 65535) + (c & 65535) + (d & 65535) + (e & 65535);
        return ((a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) + (f >>> 16) & 65535) << 16 | f & 65535
    }
    function s(a, c) {
        var d, e, f;
        d = (a.b & 65535) + (c.b & 65535);
        e = (a.b >>> 16) + (c.b >>> 16) + (d >>> 16);
        f = (e & 65535) << 16 | d & 65535;
        d = (a.a & 65535) + (c.a & 65535) + (e >>> 16);
        e = (a.a >>> 16) + (c.a >>> 16) + (d >>> 16);
        return new b((e & 65535) << 16 | d & 65535, f)
    }
    function I(a, c, d, e) {
        var f, g, h;
        f = (a.b & 65535) + (c.b & 65535) + (d.b & 65535) + (e.b & 65535);
        g = (a.b >>> 16) + (c.b >>> 16) + (d.b >>> 16) + (e.b >>> 16) + (f >>> 16);
        h = (g & 65535) << 16 | f & 65535;
        f = (a.a & 65535) + (c.a & 65535) + (d.a & 65535) + (e.a & 65535) + (g >>> 16);
        g = (a.a >>> 16) + (c.a >>> 16) + (d.a >>> 16) + (e.a >>> 16) + (f >>> 16);
        return new b((g & 65535) << 16 | f & 65535, h)
    }
    function M(a, c, d, e, f) {
        var g, h, k;
        g = (a.b & 65535) + (c.b & 65535) + (d.b & 65535) + (e.b & 65535) + (f.b & 65535);
        h = (a.b >>> 16) + (c.b >>> 16) + (d.b >>> 16) + (e.b >>> 16) + (f.b >>> 16) + (g >>> 16);
        k = (h & 65535) << 16 | g & 65535;
        g = (a.a & 65535) + (c.a & 65535) + (d.a & 65535) + (e.a & 65535) + (f.a & 65535) + (h >>> 16);
        h = (a.a >>> 16) + (c.a >>> 16) + (d.a >>> 16) + (e.a >>> 16) + (f.a >>> 16) + (g >>> 16);
        return new b((h & 65535) << 16 | g & 65535, k)
    }
    function G(a, b) {
        var c = [], d, e, f, g, h, k, n, s, G, m = [1732584193, 4023233417, 2562383102, 271733878, 3285377520], q = [1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1518500249, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 1859775393, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 2400959708, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782, 3395469782];
        a[b >>> 5] |= 128 << 24 - b % 32;
        a[(b + 65 >>> 9 << 4) + 15] = b;
        G = a.length;
        for (n = 0; n < G; n += 16) {
            d = m[0];
            e = m[1];
            f = m[2];
            g = m[3];
            h = m[4];
            for (s = 0; 80 > s; s += 1)
                c[s] = 16 > s ? a[s + n] : (c[s - 3] ^ c[s - 8] ^ c[s - 14] ^ c[s - 16]) << 1 | (c[s - 3] ^ c[s - 8] ^ c[s - 14] ^ c[s - 16]) >>> 31,
                    k = 20 > s ? L(d << 5 | d >>> 27, e & f ^ ~e & g, h, q[s], c[s]) : 40 > s ? L(d << 5 | d >>> 27, e ^ f ^ g, h, q[s], c[s]) : 60 > s ? L(d << 5 | d >>> 27, u(e, f, g), h, q[s], c[s]) : L(d << 5 | d >>> 27, e ^ f ^ g, h, q[s], c[s]),
                    h = g,
                    g = f,
                    f = e << 30 | e >>> 2,
                    e = d,
                    d = k;
            m[0] = K(d, m[0]);
            m[1] = K(e, m[1]);
            m[2] = K(f, m[2]);
            m[3] = K(g, m[3]);
            m[4] = K(h, m[4])
        }
        return m
    }
    function J(c, d, e) {
        var f, g, h, k, n, G, q, J, da, m, S, O, E, T, R, H, U, V, W, X, Y, Z, aa, ba, l, ca, P = [], ea, Q;
        "SHA-224" === e || "SHA-256" === e ? (S = 64,
            f = (d + 65 >>> 9 << 4) + 15,
            T = 16,
            R = 1,
            l = Number,
            H = K,
            U = N,
            V = L,
            W = y,
            X = A,
            Y = F,
            Z = x,
            ba = u,
            aa = r,
            ca = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298],
            m = "SHA-224" === e ? [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428] : [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]) : "SHA-384" === e || "SHA-512" === e ? (S = 80,
                f = (d + 128 >>> 10 << 5) + 31,
                T = 32,
                R = 2,
                l = b,
                H = s,
                U = I,
                V = M,
                W = v,
                X = p,
                Y = D,
                Z = B,
                ba = w,
                aa = C,
                ca = [new l(1116352408, 3609767458), new l(1899447441, 602891725), new l(3049323471, 3964484399), new l(3921009573, 2173295548), new l(961987163, 4081628472), new l(1508970993, 3053834265), new l(2453635748, 2937671579), new l(2870763221, 3664609560), new l(3624381080, 2734883394), new l(310598401, 1164996542), new l(607225278, 1323610764), new l(1426881987, 3590304994), new l(1925078388, 4068182383), new l(2162078206, 991336113), new l(2614888103, 633803317), new l(3248222580, 3479774868), new l(3835390401, 2666613458), new l(4022224774, 944711139), new l(264347078, 2341262773), new l(604807628, 2007800933), new l(770255983, 1495990901), new l(1249150122, 1856431235), new l(1555081692, 3175218132), new l(1996064986, 2198950837), new l(2554220882, 3999719339), new l(2821834349, 766784016), new l(2952996808, 2566594879), new l(3210313671, 3203337956), new l(3336571891, 1034457026), new l(3584528711, 2466948901), new l(113926993, 3758326383), new l(338241895, 168717936), new l(666307205, 1188179964), new l(773529912, 1546045734), new l(1294757372, 1522805485), new l(1396182291, 2643833823), new l(1695183700, 2343527390), new l(1986661051, 1014477480), new l(2177026350, 1206759142), new l(2456956037, 344077627), new l(2730485921, 1290863460), new l(2820302411, 3158454273), new l(3259730800, 3505952657), new l(3345764771, 106217008), new l(3516065817, 3606008344), new l(3600352804, 1432725776), new l(4094571909, 1467031594), new l(275423344, 851169720), new l(430227734, 3100823752), new l(506948616, 1363258195), new l(659060556, 3750685593), new l(883997877, 3785050280), new l(958139571, 3318307427), new l(1322822218, 3812723403), new l(1537002063, 2003034995), new l(1747873779, 3602036899), new l(1955562222, 1575990012), new l(2024104815, 1125592928), new l(2227730452, 2716904306), new l(2361852424, 442776044), new l(2428436474, 593698344), new l(2756734187, 3733110249), new l(3204031479, 2999351573), new l(3329325298, 3815920427), new l(3391569614, 3928383900), new l(3515267271, 566280711), new l(3940187606, 3454069534), new l(4118630271, 4000239992), new l(116418474, 1914138554), new l(174292421, 2731055270), new l(289380356, 3203993006), new l(460393269, 320620315), new l(685471733, 587496836), new l(852142971, 1086792851), new l(1017036298, 365543100), new l(1126000580, 2618297676), new l(1288033470, 3409855158), new l(1501505948, 4234509866), new l(1607167915, 987167468), new l(1816402316, 1246189591)],
                m = "SHA-384" === e ? [new l(3418070365, 3238371032), new l(1654270250, 914150663), new l(2438529370, 812702999), new l(355462360, 4144912697), new l(1731405415, 4290775857), new l(41048885895, 1750603025), new l(3675008525, 1694076839), new l(1203062813, 3204075428)] : [new l(1779033703, 4089235720), new l(3144134277, 2227873595), new l(1013904242, 4271175723), new l(2773480762, 1595750129), new l(1359893119, 2917565137), new l(2600822924, 725511199), new l(528734635, 4215389547), new l(1541459225, 327033209)]) : a("Unexpected error in SHA-2 implementation");
        c[d >>> 5] |= 128 << 24 - d % 32;
        c[f] = d;
        ea = c.length;
        for (O = 0; O < ea; O += T) {
            d = m[0];
            f = m[1];
            g = m[2];
            h = m[3];
            k = m[4];
            n = m[5];
            G = m[6];
            q = m[7];
            for (E = 0; E < S; E += 1)
                P[E] = 16 > E ? new l(c[E * R + O], c[E * R + O + 1]) : U(X(P[E - 2]), P[E - 7], W(P[E - 15]), P[E - 16]),
                    J = V(q, Z(k), aa(k, n, G), ca[E], P[E]),
                    da = H(Y(d), ba(d, f, g)),
                    q = G,
                    G = n,
                    n = k,
                    k = H(h, J),
                    h = g,
                    g = f,
                    f = d,
                    d = H(J, da);
            m[0] = H(d, m[0]);
            m[1] = H(f, m[1]);
            m[2] = H(g, m[2]);
            m[3] = H(h, m[3]);
            m[4] = H(k, m[4]);
            m[5] = H(n, m[5]);
            m[6] = H(G, m[6]);
            m[7] = H(q, m[7])
        }
        "SHA-224" === e ? Q = [m[0], m[1], m[2], m[3], m[4], m[5], m[6]] : "SHA-256" === e ? Q = m : "SHA-384" === e ? Q = [m[0].a, m[0].b, m[1].a, m[1].b, m[2].a, m[2].b, m[3].a, m[3].b, m[4].a, m[4].b, m[5].a, m[5].b] : "SHA-512" === e ? Q = [m[0].a, m[0].b, m[1].a, m[1].b, m[2].a, m[2].b, m[3].a, m[3].b, m[4].a, m[4].b, m[5].a, m[5].b, m[6].a, m[6].b, m[7].a, m[7].b] : a("Unexpected error in SHA-2 implementation");
        return Q
    }
    window.jsSHA = function (b, k, s) {
        var n = null
            , q = null
            , u = null
            , r = null
            , v = null
            , I = 0
            , M = [0]
            , x = 0
            , p = null
            , x = "undefined" !== typeof s ? s : 8;
        8 === x || 16 === x || a("charSize must be 8 or 16");
        "HEX" === k ? (0 !== b.length % 2 && a("srcString of HEX type must be in byte increments"),
            p = d(b),
            I = p.binLen,
            M = p.value) : "ASCII" === k || "TEXT" === k ? (p = c(b, x),
                I = p.binLen,
                M = p.value) : "B64" === k ? (p = e(b),
                    I = p.binLen,
                    M = p.value) : a("inputFormat must be HEX, TEXT, ASCII, or B64");
        this.getHash = function (b, c, d) {
            var e = null
                , k = M.slice()
                , s = "";
            switch (c) {
                case "HEX":
                    e = f;
                    break;
                case "B64":
                    e = g;
                    break;
                default:
                    a("format must be HEX or B64")
            }
            "SHA-1" === b ? (null === n && (n = G(k, I)),
                s = e(n, h(d))) : "SHA-224" === b ? (null === q && (q = J(k, I, b)),
                    s = e(q, h(d))) : "SHA-256" === b ? (null === u && (u = J(k, I, b)),
                        s = e(u, h(d))) : "SHA-384" === b ? (null === r && (r = J(k, I, b)),
                            s = e(r, h(d))) : "SHA-512" === b ? (null === v && (v = J(k, I, b)),
                                s = e(v, h(d))) : a("Chosen SHA variant is not supported");
            return s
        }
            ;
        this.getHMAC = function (b, k, s, n, q) {
            var u, r, p, v, w, A = [], B = [], y = null;
            switch (n) {
                case "HEX":
                    u = f;
                    break;
                case "B64":
                    u = g;
                    break;
                default:
                    a("outputFormat must be HEX or B64")
            }
            "SHA-1" === s ? (p = 64,
                w = 160) : "SHA-224" === s ? (p = 64,
                    w = 224) : "SHA-256" === s ? (p = 64,
                        w = 256) : "SHA-384" === s ? (p = 128,
                            w = 384) : "SHA-512" === s ? (p = 128,
                                w = 512) : a("Chosen SHA variant is not supported");
            "HEX" === k ? (y = d(b),
                v = y.binLen,
                r = y.value) : "ASCII" === k || "TEXT" === k ? (y = c(b, x),
                    v = y.binLen,
                    r = y.value) : "B64" === k ? (y = e(b),
                        v = y.binLen,
                        r = y.value) : a("inputFormat must be HEX, TEXT, ASCII, or B64");
            b = 8 * p;
            k = p / 4 - 1;
            p < v / 8 ? (r = "SHA-1" === s ? G(r, v) : J(r, v, s),
                r[k] &= 4294967040) : p > v / 8 && (r[k] &= 4294967040);
            for (p = 0; p <= k; p += 1)
                A[p] = r[p] ^ 909522486,
                    B[p] = r[p] ^ 1549556828;
            s = "SHA-1" === s ? G(B.concat(G(A.concat(M), b + I)), b + w) : J(B.concat(J(A.concat(M), b + I, s)), b + w, s);
            return u(s, h(q))
        }
    }
}
)();
function SRP() {
    function a(a) {
        for (var b = "", c = -1, d, e; ++c < a.length;)
            d = a.charCodeAt(c),
                e = c + 1 < a.length ? a.charCodeAt(c + 1) : 0,
                55296 <= d && (56319 >= d && 56320 <= e && 57343 >= e) && (d = 65536 + ((d & 1023) << 10) + (e & 1023),
                    c++),
                127 >= d ? b += String.fromCharCode(d) : 2047 >= d ? b += String.fromCharCode(192 | d >>> 6 & 31, 128 | d & 63) : 65535 >= d ? b += String.fromCharCode(224 | d >>> 12 & 15, 128 | d >>> 6 & 63, 128 | d & 63) : 2097151 >= d && (b += String.fromCharCode(240 | d >>> 18 & 7, 128 | d >>> 12 & 63, 128 | d >>> 6 & 63, 128 | d & 63));
        return b
    }
    function b(a, b, c) {
        p.error_message(a.status)
    }
    function c(a) {
        f(a.s, a.B).done(function () {
            $.post(A, {
                CSRFtoken: $("meta[name\x3dCSRFtoken]").attr("content"),
                M: y
            }, g, "json").fail(b)
        }).fail(function () {
            a.error ? p.error_message(a.error) : p.error_message("failed")
        })
    }
    function d(a, b) {
        return (new jsSHA(a, b)).getHash("SHA-256", "HEX")
    }
    function e(a, b) {
        var c = a.toByteArray()
            , e = b.toByteArray();
        c.length > q && c.shift();
        e.length > q && e.shift();
        for (var f = Array(q - c.length), g = 0, h = f.length; g < h; g++)
            f[g] = 0;
        for (var k = Array(q - e.length), g = 0, h = k.length; g < h; g++)
            k[g] = 0;
        c = f.concat(c, k, e);
        return d(String.fromCharCode.apply(null, c), "TEXT")
    }
    function f(b, c) {
        var f = $.Deferred();
        if (!b || !c)
            return f.reject(),
                f.promise();
        var g = new BigInteger(c, 16)
            , h = new BigInteger(e(D, g), 16);
        if (g.mod(k).equals(BigInteger.ZERO) || h.equals(BigInteger.ZERO))
            return f.reject(),
                f.promise();
        var n = new BigInteger(d(b + d(a(N + ":" + L), "TEXT"), "HEX"), 16);
        r.modPowPromise(n, k).then(function (a) {
            return C.multiply(a).mod(k)
        }).then(function (a) {
            var b = F.add(h.multiply(n).mod(k)).mod(k);
            return g.subtract(a).mod(k).modPowPromise(b, k)
        }).done(function (e) {
            e = e.toString(16);
            1 == e.length % 2 && (e = "0" + e);
            B = d(e, "HEX");
            e = d(a(N), "TEXT");
            y = d(u + e + b + x + c + B, "HEX");
            v = d(x + y + B, "HEX");
            f.resolve()
        }).fail(function () {
            f.reject()
        });
        return f.promise()
    }
    function g(a) {
        a.M && a.M == v.toUpperCase() ? (K = !0,
            p.success()) : a.error ? p.error_message(a.error) : p.error_message("failed")
    }
    function h(a) {
        1 > a && (a = 1);
        var b = new SecureRandom;
        a = (new BigInteger(4 * a, b)).toString(16);
        1 == a.length % 2 && (a = "0" + a);
        return a
    }
    function n(a) {
        a.success ? p.passwordchanged() : a.error ? p.error_message(a.error) : p.error_message("failed")
    }
    var k = new BigInteger("ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73", 16)
        , q = 256
        , r = new BigInteger("2")
        , C = new BigInteger("05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300", 16)
        , u = "4a76a9a2402bdd18123389b72ebbda50a30f65aedb90d7273130edea4b29cc4c"
        , w = new SecureRandom
        , F = new BigInteger(256, w)
        , D = null
        , x = null
        , B = null
        , y = null
        , v = null
        , A = ""
        , p = this
        , K = !1
        , N = ""
        , L = "";
    this.identify = function (a, d, e) {
        function f(a) {
            a.mod(k).equals(BigInteger.ZERO) ? (F = new BigInteger(256, w),
                r.modPowPromise(F, k).done(f)) : (D = a,
                    x = D.toString(16),
                    1 == x.length % 2 && (x = "0" + x),
                    $.post(A, {
                        CSRFtoken: $("meta[name\x3dCSRFtoken]").attr("content"),
                        I: N,
                        A: x
                    }, c, "json").fail(b))
        }
        A = a;
        N = d;
        L = e;
        r.modPowPromise(F, k).done(f)
    }
        ;
    this.generateSaltAndVerifierTheCallback = function (b, c, e) {
        var f = h(8);
        b = new BigInteger(d(f + d(a(b + ":" + c), "TEXT"), "HEX"), 16);
        r.modPowPromise(b, k).done(function (a) {
            a = a.toString(16);
            1 == a.length % 2 && (a = "0" + a);
            var b;
            b = h(16);
            b = sha512crypt(c, b);
            e(f, a, b)
        })
    }
        ;
    this.generateSaltAndVerifier = function (a, c, d) {
        A = a;
        p.generateSaltAndVerifierTheCallback(c, d, function (a, c, d) {
            $.post(A, {
                CSRFtoken: $("meta[name\x3dCSRFtoken]").attr("content"),
                salt: a,
                verifier: c,
                cryptedpassword: d
            }, n, "json").fail(b)
        })
    }
        ;
    this.success = function () {
        alert("Login successful.")
    }
        ;
    this.passwordchanged = function () {
        alert("Password changed.")
    }
        ;
    this.key = function () {
        return null != B && K ? B : null
    }
        ;
    this.error_message = function (a) {
        alert(a)
    }
}
"undefined" !== typeof exports && (rstr_sha512 = require("./lib/sha512.js").rstr_sha512,
    binb_sha512 = require("./lib/sha512.js").binb_sha512,
    hex_sha512 = require("./lib/sha512.js").hex_sha512,
    rstr2hex = require("./lib/sha512.js").rstr2hex,
    rstr2b64 = require("./lib/sha512.js").rstr2b64);
function _extend(a, b) {
    var c = "";
    for (i = 0; i < Math.floor(b / 64); i++)
        c += a;
    return c += a.substr(0, b % 64)
}
function _sha512crypt_intermediate(a, b) {
    rstr_sha512(a + b);
    var c = rstr_sha512(a + b + a)
        , d = a.length
        , e = _extend(c, a.length)
        , e = a + b + e;
    for (cnt = d; 0 < cnt; cnt >>= 1)
        e = 0 != (cnt & 1) ? e + c : e + a;
    return rstr_sha512(e)
}
function _rstr_sha512crypt(a, b, c) {
    var d = _sha512crypt_intermediate(a, b)
        , e = "";
    for (i = 0; i < a.length; i++)
        e += a;
    e = rstr_sha512(e);
    a = _extend(e, a.length);
    e = "";
    for (i = 0; i < 16 + d.charCodeAt(0); i++)
        e += b;
    e = rstr_sha512(e);
    b = _extend(e, b.length);
    e = "";
    for (i = 0; i < c; i++)
        e = "",
            e = i & 1 ? e + a : e + d,
            i % 3 && (e += b),
            i % 7 && (e += a),
            e = i & 1 ? e + d : e + a,
            d = rstr_sha512(e);
    return d
}
function sha512crypt(a, b) {
    var c = "$6$"
        , d = 5E3
        , e = b.split("$");
    if (1 < e.length) {
        if ("6" !== e[1])
            throw Error("Got '" + b + "' but only SHA512 ($6$) algorithm supported");
        d = parseInt(e[2].split("\x3d")[1]) || 5E3;
        1E3 > d && (d = 1E3);
        999999999 < d && (d = 999999999);
        b = e[3] || b
    }
    b = b.substr(0, 16);
    var f = _rstr_sha512crypt(a, b, d)
        , g = ""
        , h = [42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47, 48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52, 31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63];
    for (i = 0; i < f.length; i += 3)
        void 0 === h[i + 1] ? (char_1 = f.charCodeAt(h[i + 0]) & 63,
            char_2 = (f.charCodeAt(h[i + 0]) & 192) >>> 6,
            g += "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(char_1) + "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(char_2)) : (char_1 = f.charCodeAt(h[i + 0]) & 63,
                char_2 = (f.charCodeAt(h[i + 0]) & 192) >>> 6 | (f.charCodeAt(h[i + 1]) & 15) << 2,
                char_3 = (f.charCodeAt(h[i + 1]) & 240) >> 4 | (f.charCodeAt(h[i + 2]) & 3) << 4,
                char_4 = (f.charCodeAt(h[i + 2]) & 252) >>> 2,
                g += "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(char_1) + "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(char_2) + "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(char_3) + "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".charAt(char_4));
    2 < e.length && (c = "$6$rounds\x3d" + d + "$");
    return c + b + "$" + g
}
"undefined" !== typeof exports && (exports._sha512crypt_intermediate = _sha512crypt_intermediate,
    exports._rstr_sha512crypt = _rstr_sha512crypt,
    exports.b64_sha512crypt = sha512crypt,
    exports.sha512crypt = sha512crypt);
var hexcase = 0
    , b64pad = "";
function hex_sha512(a) {
    return rstr2hex(rstr_sha512(str2rstr_utf8(a)))
}
function b64_sha512(a) {
    return rstr2b64(rstr_sha512(str2rstr_utf8(a)))
}
function any_sha512(a, b) {
    return rstr2any(rstr_sha512(str2rstr_utf8(a)), b)
}
function hex_hmac_sha512(a, b) {
    return rstr2hex(rstr_hmac_sha512(str2rstr_utf8(a), str2rstr_utf8(b)))
}
function b64_hmac_sha512(a, b) {
    return rstr2b64(rstr_hmac_sha512(str2rstr_utf8(a), str2rstr_utf8(b)))
}
function any_hmac_sha512(a, b, c) {
    return rstr2any(rstr_hmac_sha512(str2rstr_utf8(a), str2rstr_utf8(b)), c)
}
function sha512_vm_test() {
    return "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == hex_sha512("abc").toLowerCase()
}
function rstr_sha512(a) {
    return binb2rstr(binb_sha512(rstr2binb(a), 8 * a.length))
}
function rstr_hmac_sha512(a, b) {
    var c = rstr2binb(a);
    32 < c.length && (c = binb_sha512(c, 8 * a.length));
    for (var d = Array(32), e = Array(32), f = 0; 32 > f; f++)
        d[f] = c[f] ^ 909522486,
            e[f] = c[f] ^ 1549556828;
    c = binb_sha512(d.concat(rstr2binb(b)), 1024 + 8 * b.length);
    return binb2rstr(binb_sha512(e.concat(c), 1536))
}
function rstr2hex(a) {
    try {
        hexcase
    } catch (b) {
        hexcase = 0
    }
    for (var c = hexcase ? "0123456789ABCDEF" : "0123456789abcdef", d = "", e, f = 0; f < a.length; f++)
        e = a.charCodeAt(f),
            d += c.charAt(e >>> 4 & 15) + c.charAt(e & 15);
    return d
}
function rstr2b64(a) {
    try {
        b64pad
    } catch (b) {
        b64pad = ""
    }
    for (var c = "", d = a.length, e = 0; e < d; e += 3)
        for (var f = a.charCodeAt(e) << 16 | (e + 1 < d ? a.charCodeAt(e + 1) << 8 : 0) | (e + 2 < d ? a.charCodeAt(e + 2) : 0), g = 0; 4 > g; g++)
            c = 8 * e + 6 * g > 8 * a.length ? c + b64pad : c + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(f >>> 6 * (3 - g) & 63);
    return c
}
function rstr2any(a, b) {
    var c = b.length, d, e, f, g, h, n = Array(Math.ceil(a.length / 2));
    for (d = 0; d < n.length; d++)
        n[d] = a.charCodeAt(2 * d) << 8 | a.charCodeAt(2 * d + 1);
    var k = Math.ceil(8 * a.length / (Math.log(b.length) / Math.log(2)))
        , q = Array(k);
    for (e = 0; e < k; e++) {
        h = [];
        for (d = g = 0; d < n.length; d++)
            if (g = (g << 16) + n[d],
                f = Math.floor(g / c),
                g -= f * c,
                0 < h.length || 0 < f)
                h[h.length] = f;
        q[e] = g;
        n = h
    }
    c = "";
    for (d = q.length - 1; 0 <= d; d--)
        c += b.charAt(q[d]);
    return c
}
function str2rstr_utf8(a) {
    for (var b = "", c = -1, d, e; ++c < a.length;)
        d = a.charCodeAt(c),
            e = c + 1 < a.length ? a.charCodeAt(c + 1) : 0,
            55296 <= d && (56319 >= d && 56320 <= e && 57343 >= e) && (d = 65536 + ((d & 1023) << 10) + (e & 1023),
                c++),
            127 >= d ? b += String.fromCharCode(d) : 2047 >= d ? b += String.fromCharCode(192 | d >>> 6 & 31, 128 | d & 63) : 65535 >= d ? b += String.fromCharCode(224 | d >>> 12 & 15, 128 | d >>> 6 & 63, 128 | d & 63) : 2097151 >= d && (b += String.fromCharCode(240 | d >>> 18 & 7, 128 | d >>> 12 & 63, 128 | d >>> 6 & 63, 128 | d & 63));
    return b
}
function str2rstr_utf16le(a) {
    for (var b = "", c = 0; c < a.length; c++)
        b += String.fromCharCode(a.charCodeAt(c) & 255, a.charCodeAt(c) >>> 8 & 255);
    return b
}
function str2rstr_utf16be(a) {
    for (var b = "", c = 0; c < a.length; c++)
        b += String.fromCharCode(a.charCodeAt(c) >>> 8 & 255, a.charCodeAt(c) & 255);
    return b
}
function rstr2binb(a) {
    for (var b = Array(a.length >> 2), c = 0; c < b.length; c++)
        b[c] = 0;
    for (c = 0; c < 8 * a.length; c += 8)
        b[c >> 5] |= (a.charCodeAt(c / 8) & 255) << 24 - c % 32;
    return b
}
function binb2rstr(a) {
    for (var b = "", c = 0; c < 32 * a.length; c += 8)
        b += String.fromCharCode(a[c >> 5] >>> 24 - c % 32 & 255);
    return b
}
var sha512_k;
function binb_sha512(a, b) {
    void 0 == sha512_k && (sha512_k = [new int64(1116352408, -685199838), new int64(1899447441, 602891725), new int64(-1245643825, -330482897), new int64(-373957723, -2121671748), new int64(961987163, -213338824), new int64(1508970993, -1241133031), new int64(-1841331548, -1357295717), new int64(-1424204075, -630357736), new int64(-670586216, -1560083902), new int64(310598401, 1164996542), new int64(607225278, 1323610764), new int64(1426881987, -704662302), new int64(1925078388, -226784913), new int64(-2132889090, 991336113), new int64(-1680079193, 633803317), new int64(-1046744716, -815192428), new int64(-459576895, -1628353838), new int64(-272742522, 944711139), new int64(264347078, -1953704523), new int64(604807628, 2007800933), new int64(770255983, 1495990901), new int64(1249150122, 1856431235), new int64(1555081692, -1119749164), new int64(1996064986, -2096016459), new int64(-1740746414, -295247957), new int64(-1473132947, 766784016), new int64(-1341970488, -1728372417), new int64(-1084653625, -1091629340), new int64(-958395405, 1034457026), new int64(-710438585, -1828018395), new int64(113926993, -536640913), new int64(338241895, 168717936), new int64(666307205, 1188179964), new int64(773529912, 1546045734), new int64(1294757372, 1522805485), new int64(1396182291, -1651133473), new int64(1695183700, -1951439906), new int64(1986661051, 1014477480), new int64(-2117940946, 1206759142), new int64(-1838011259, 344077627), new int64(-1564481375, 1290863460), new int64(-1474664885, -1136513023), new int64(-1035236496, -789014639), new int64(-949202525, 106217008), new int64(-778901479, -688958952), new int64(-694614492, 1432725776), new int64(-200395387, 1467031594), new int64(275423344, 851169720), new int64(430227734, -1194143544), new int64(506948616, 1363258195), new int64(659060556, -544281703), new int64(883997877, -509917016), new int64(958139571, -976659869), new int64(1322822218, -482243893), new int64(1537002063, 2003034995), new int64(1747873779, -692930397), new int64(1955562222, 1575990012), new int64(2024104815, 1125592928), new int64(-2067236844, -1578062990), new int64(-1933114872, 442776044), new int64(-1866530822, 593698344), new int64(-1538233109, -561857047), new int64(-1090935817, -1295615723), new int64(-965641998, -479046869), new int64(-903397682, -366583396), new int64(-779700025, 566280711), new int64(-354779690, -840897762), new int64(-176337025, -294727304), new int64(116418474, 1914138554), new int64(174292421, -1563912026), new int64(289380356, -1090974290), new int64(460393269, 320620315), new int64(685471733, 587496836), new int64(852142971, 1086792851), new int64(1017036298, 365543100), new int64(1126000580, -1676669620), new int64(1288033470, -885112138), new int64(1501505948, -60457430), new int64(1607167915, 987167468), new int64(1816402316, 1246189591)]);
    var c = [new int64(1779033703, -205731576), new int64(-1150833019, -2067093701), new int64(1013904242, -23791573), new int64(-1521486534, 1595750129), new int64(1359893119, -1377402159), new int64(-1694144372, 725511199), new int64(528734635, -79577749), new int64(1541459225, 327033209)], d = new int64(0, 0), e = new int64(0, 0), f = new int64(0, 0), g = new int64(0, 0), h = new int64(0, 0), n = new int64(0, 0), k = new int64(0, 0), q = new int64(0, 0), r = new int64(0, 0), C = new int64(0, 0), u = new int64(0, 0), w = new int64(0, 0), F = new int64(0, 0), D = new int64(0, 0), x = new int64(0, 0), B = new int64(0, 0), y = new int64(0, 0), v, A, p = Array(80);
    for (A = 0; 80 > A; A++)
        p[A] = new int64(0, 0);
    a[b >> 5] |= 128 << 24 - (b & 31);
    a[(b + 128 >> 10 << 5) + 31] = b;
    for (A = 0; A < a.length; A += 32) {
        int64copy(f, c[0]);
        int64copy(g, c[1]);
        int64copy(h, c[2]);
        int64copy(n, c[3]);
        int64copy(k, c[4]);
        int64copy(q, c[5]);
        int64copy(r, c[6]);
        int64copy(C, c[7]);
        for (v = 0; 16 > v; v++)
            p[v].h = a[A + 2 * v],
                p[v].l = a[A + 2 * v + 1];
        for (v = 16; 80 > v; v++)
            int64rrot(x, p[v - 2], 19),
                int64revrrot(B, p[v - 2], 29),
                int64shr(y, p[v - 2], 6),
                w.l = x.l ^ B.l ^ y.l,
                w.h = x.h ^ B.h ^ y.h,
                int64rrot(x, p[v - 15], 1),
                int64rrot(B, p[v - 15], 8),
                int64shr(y, p[v - 15], 7),
                u.l = x.l ^ B.l ^ y.l,
                u.h = x.h ^ B.h ^ y.h,
                int64add4(p[v], w, p[v - 7], u, p[v - 16]);
        for (v = 0; 80 > v; v++)
            F.l = k.l & q.l ^ ~k.l & r.l,
                F.h = k.h & q.h ^ ~k.h & r.h,
                int64rrot(x, k, 14),
                int64rrot(B, k, 18),
                int64revrrot(y, k, 9),
                w.l = x.l ^ B.l ^ y.l,
                w.h = x.h ^ B.h ^ y.h,
                int64rrot(x, f, 28),
                int64revrrot(B, f, 2),
                int64revrrot(y, f, 7),
                u.l = x.l ^ B.l ^ y.l,
                u.h = x.h ^ B.h ^ y.h,
                D.l = f.l & g.l ^ f.l & h.l ^ g.l & h.l,
                D.h = f.h & g.h ^ f.h & h.h ^ g.h & h.h,
                int64add5(d, C, w, F, sha512_k[v], p[v]),
                int64add(e, u, D),
                int64copy(C, r),
                int64copy(r, q),
                int64copy(q, k),
                int64add(k, n, d),
                int64copy(n, h),
                int64copy(h, g),
                int64copy(g, f),
                int64add(f, d, e);
        int64add(c[0], c[0], f);
        int64add(c[1], c[1], g);
        int64add(c[2], c[2], h);
        int64add(c[3], c[3], n);
        int64add(c[4], c[4], k);
        int64add(c[5], c[5], q);
        int64add(c[6], c[6], r);
        int64add(c[7], c[7], C)
    }
    d = Array(16);
    for (A = 0; 8 > A; A++)
        d[2 * A] = c[A].h,
            d[2 * A + 1] = c[A].l;
    return d
}
function int64(a, b) {
    this.h = a;
    this.l = b
}
function int64copy(a, b) {
    a.h = b.h;
    a.l = b.l
}
function int64rrot(a, b, c) {
    a.l = b.l >>> c | b.h << 32 - c;
    a.h = b.h >>> c | b.l << 32 - c
}
function int64revrrot(a, b, c) {
    a.l = b.h >>> c | b.l << 32 - c;
    a.h = b.l >>> c | b.h << 32 - c
}
function int64shr(a, b, c) {
    a.l = b.l >>> c | b.h << 32 - c;
    a.h = b.h >>> c
}
function int64add(a, b, c) {
    var d = (b.l & 65535) + (c.l & 65535)
        , e = (b.l >>> 16) + (c.l >>> 16) + (d >>> 16)
        , f = (b.h & 65535) + (c.h & 65535) + (e >>> 16);
    b = (b.h >>> 16) + (c.h >>> 16) + (f >>> 16);
    a.l = d & 65535 | e << 16;
    a.h = f & 65535 | b << 16
}
function int64add4(a, b, c, d, e) {
    var f = (b.l & 65535) + (c.l & 65535) + (d.l & 65535) + (e.l & 65535)
        , g = (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (f >>> 16)
        , h = (b.h & 65535) + (c.h & 65535) + (d.h & 65535) + (e.h & 65535) + (g >>> 16);
    b = (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (h >>> 16);
    a.l = f & 65535 | g << 16;
    a.h = h & 65535 | b << 16
}
function int64add5(a, b, c, d, e, f) {
    var g = (b.l & 65535) + (c.l & 65535) + (d.l & 65535) + (e.l & 65535) + (f.l & 65535)
        , h = (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (f.l >>> 16) + (g >>> 16)
        , n = (b.h & 65535) + (c.h & 65535) + (d.h & 65535) + (e.h & 65535) + (f.h & 65535) + (h >>> 16);
    b = (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (f.h >>> 16) + (n >>> 16);
    a.l = g & 65535 | h << 16;
    a.h = n & 65535 | b << 16
}
"undefined" !== typeof exports && (exports.rstr_sha512 = rstr_sha512,
    exports.rstr2hex = rstr2hex,
    exports.b64_hmac_sha512 = b64_hmac_sha512);
