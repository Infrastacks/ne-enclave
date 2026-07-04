import { makeGenericClientConstructor, credentials, Metadata, status } from '@grpc/grpc-js';

// src/client.ts

// node_modules/@bufbuild/protobuf/dist/esm/wire/varint.js
function varint64read() {
  let lowBits = 0;
  let highBits = 0;
  for (let shift = 0; shift < 28; shift += 7) {
    let b = this.buf[this.pos++];
    lowBits |= (b & 127) << shift;
    if ((b & 128) == 0) {
      this.assertBounds();
      return [lowBits, highBits];
    }
  }
  let middleByte = this.buf[this.pos++];
  lowBits |= (middleByte & 15) << 28;
  highBits = (middleByte & 112) >> 4;
  if ((middleByte & 128) == 0) {
    this.assertBounds();
    return [lowBits, highBits];
  }
  for (let shift = 3; shift <= 31; shift += 7) {
    let b = this.buf[this.pos++];
    highBits |= (b & 127) << shift;
    if ((b & 128) == 0) {
      this.assertBounds();
      return [lowBits, highBits];
    }
  }
  throw new Error("invalid varint");
}
function varint64write(lo, hi, bytes) {
  for (let i = 0; i < 28; i = i + 7) {
    const shift = lo >>> i;
    const hasNext = !(shift >>> 7 == 0 && hi == 0);
    const byte = (hasNext ? shift | 128 : shift) & 255;
    bytes.push(byte);
    if (!hasNext) {
      return;
    }
  }
  const splitBits = lo >>> 28 & 15 | (hi & 7) << 4;
  const hasMoreBits = !(hi >> 3 == 0);
  bytes.push((hasMoreBits ? splitBits | 128 : splitBits) & 255);
  if (!hasMoreBits) {
    return;
  }
  for (let i = 3; i < 31; i = i + 7) {
    const shift = hi >>> i;
    const hasNext = !(shift >>> 7 == 0);
    const byte = (hasNext ? shift | 128 : shift) & 255;
    bytes.push(byte);
    if (!hasNext) {
      return;
    }
  }
  bytes.push(hi >>> 31 & 1);
}
var TWO_PWR_32_DBL = 4294967296;
function int64FromString(dec) {
  const minus = dec[0] === "-";
  if (minus) {
    dec = dec.slice(1);
  }
  const base = 1e6;
  let lowBits = 0;
  let highBits = 0;
  function add1e6digit(begin, end) {
    const digit1e6 = Number(dec.slice(begin, end));
    highBits *= base;
    lowBits = lowBits * base + digit1e6;
    if (lowBits >= TWO_PWR_32_DBL) {
      highBits = highBits + (lowBits / TWO_PWR_32_DBL | 0);
      lowBits = lowBits % TWO_PWR_32_DBL;
    }
  }
  add1e6digit(-24, -18);
  add1e6digit(-18, -12);
  add1e6digit(-12, -6);
  add1e6digit(-6);
  return minus ? negate(lowBits, highBits) : newBits(lowBits, highBits);
}
function int64ToString(lo, hi) {
  let bits = newBits(lo, hi);
  const negative = bits.hi & 2147483648;
  if (negative) {
    bits = negate(bits.lo, bits.hi);
  }
  const result = uInt64ToString(bits.lo, bits.hi);
  return negative ? "-" + result : result;
}
function uInt64ToString(lo, hi) {
  ({ lo, hi } = toUnsigned(lo, hi));
  if (hi <= 2097151) {
    return String(TWO_PWR_32_DBL * hi + lo);
  }
  const low = lo & 16777215;
  const mid = (lo >>> 24 | hi << 8) & 16777215;
  const high = hi >> 16 & 65535;
  let digitA = low + mid * 6777216 + high * 6710656;
  let digitB = mid + high * 8147497;
  let digitC = high * 2;
  const base = 1e7;
  if (digitA >= base) {
    digitB += Math.floor(digitA / base);
    digitA %= base;
  }
  if (digitB >= base) {
    digitC += Math.floor(digitB / base);
    digitB %= base;
  }
  return digitC.toString() + decimalFrom1e7WithLeadingZeros(digitB) + decimalFrom1e7WithLeadingZeros(digitA);
}
function toUnsigned(lo, hi) {
  return { lo: lo >>> 0, hi: hi >>> 0 };
}
function newBits(lo, hi) {
  return { lo: lo | 0, hi: hi | 0 };
}
function negate(lowBits, highBits) {
  highBits = ~highBits;
  if (lowBits) {
    lowBits = ~lowBits + 1;
  } else {
    highBits += 1;
  }
  return newBits(lowBits, highBits);
}
var decimalFrom1e7WithLeadingZeros = (digit1e7) => {
  const partial = String(digit1e7);
  return "0000000".slice(partial.length) + partial;
};
function varint32write(value, bytes) {
  if (value >= 0) {
    while (value > 127) {
      bytes.push(value & 127 | 128);
      value = value >>> 7;
    }
    bytes.push(value);
  } else {
    for (let i = 0; i < 9; i++) {
      bytes.push(value & 127 | 128);
      value = value >> 7;
    }
    bytes.push(1);
  }
}
function varint32read() {
  let b = this.buf[this.pos++];
  let result = b & 127;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 127) << 7;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 127) << 14;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 127) << 21;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 15) << 28;
  for (let readBytes = 5; (b & 128) !== 0 && readBytes < 10; readBytes++)
    b = this.buf[this.pos++];
  if ((b & 128) != 0)
    throw new Error("invalid varint");
  this.assertBounds();
  return result >>> 0;
}

// node_modules/@bufbuild/protobuf/dist/esm/proto-int64.js
var protoInt64 = /* @__PURE__ */ makeInt64Support();
function makeInt64Support() {
  const dv = new DataView(new ArrayBuffer(8));
  const ok = typeof BigInt === "function" && typeof dv.getBigInt64 === "function" && typeof dv.getBigUint64 === "function" && typeof dv.setBigInt64 === "function" && typeof dv.setBigUint64 === "function" && (!!globalThis.Deno || typeof process != "object" || typeof process.env != "object" || process.env.BUF_BIGINT_DISABLE !== "1");
  if (ok) {
    const MIN = BigInt("-9223372036854775808");
    const MAX = BigInt("9223372036854775807");
    const UMIN = BigInt("0");
    const UMAX = BigInt("18446744073709551615");
    return {
      zero: BigInt(0),
      supported: true,
      parse(value) {
        const bi = typeof value == "bigint" ? value : BigInt(value);
        if (bi > MAX || bi < MIN) {
          throw new Error(`invalid int64: ${value}`);
        }
        return bi;
      },
      uParse(value) {
        const bi = typeof value == "bigint" ? value : BigInt(value);
        if (bi > UMAX || bi < UMIN) {
          throw new Error(`invalid uint64: ${value}`);
        }
        return bi;
      },
      enc(value) {
        dv.setBigInt64(0, this.parse(value), true);
        return {
          lo: dv.getInt32(0, true),
          hi: dv.getInt32(4, true)
        };
      },
      uEnc(value) {
        dv.setBigInt64(0, this.uParse(value), true);
        return {
          lo: dv.getInt32(0, true),
          hi: dv.getInt32(4, true)
        };
      },
      dec(lo, hi) {
        dv.setInt32(0, lo, true);
        dv.setInt32(4, hi, true);
        return dv.getBigInt64(0, true);
      },
      uDec(lo, hi) {
        dv.setInt32(0, lo, true);
        dv.setInt32(4, hi, true);
        return dv.getBigUint64(0, true);
      }
    };
  }
  return {
    zero: "0",
    supported: false,
    parse(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertInt64String(value);
      return value;
    },
    uParse(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertUInt64String(value);
      return value;
    },
    enc(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertInt64String(value);
      return int64FromString(value);
    },
    uEnc(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertUInt64String(value);
      return int64FromString(value);
    },
    dec(lo, hi) {
      return int64ToString(lo, hi);
    },
    uDec(lo, hi) {
      return uInt64ToString(lo, hi);
    }
  };
}
function assertInt64String(value) {
  if (!/^-?[0-9]+$/.test(value)) {
    throw new Error("invalid int64: " + value);
  }
}
function assertUInt64String(value) {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error("invalid uint64: " + value);
  }
}

// node_modules/@bufbuild/protobuf/dist/esm/wire/text-encoding.js
var symbol = /* @__PURE__ */ Symbol.for("@bufbuild/protobuf/text-encoding");
function getTextEncoding() {
  if (globalThis[symbol] == void 0) {
    const te = new globalThis.TextEncoder();
    const td = new globalThis.TextDecoder();
    let tdStrict;
    globalThis[symbol] = {
      encodeUtf8(text) {
        return te.encode(text);
      },
      decodeUtf8(bytes, strict) {
        if (strict) {
          if (tdStrict === void 0) {
            tdStrict = new globalThis.TextDecoder("utf-8", { fatal: true });
          }
          return tdStrict.decode(bytes);
        }
        return td.decode(bytes);
      },
      checkUtf8(text) {
        try {
          encodeURIComponent(text);
          return true;
        } catch (_) {
          return false;
        }
      }
    };
  }
  return globalThis[symbol];
}

// node_modules/@bufbuild/protobuf/dist/esm/wire/binary-encoding.js
var WireType;
(function(WireType2) {
  WireType2[WireType2["Varint"] = 0] = "Varint";
  WireType2[WireType2["Bit64"] = 1] = "Bit64";
  WireType2[WireType2["LengthDelimited"] = 2] = "LengthDelimited";
  WireType2[WireType2["StartGroup"] = 3] = "StartGroup";
  WireType2[WireType2["EndGroup"] = 4] = "EndGroup";
  WireType2[WireType2["Bit32"] = 5] = "Bit32";
})(WireType || (WireType = {}));
var FLOAT32_MAX = 34028234663852886e22;
var FLOAT32_MIN = -34028234663852886e22;
var UINT32_MAX = 4294967295;
var INT32_MAX = 2147483647;
var INT32_MIN = -2147483648;
var BinaryWriter = class {
  constructor(encodeUtf8 = getTextEncoding().encodeUtf8) {
    this.encodeUtf8 = encodeUtf8;
    this.stack = [];
    this.chunks = [];
    this.buf = [];
  }
  /**
   * Return all bytes written and reset this writer.
   */
  finish() {
    if (this.buf.length) {
      this.chunks.push(new Uint8Array(this.buf));
      this.buf = [];
    }
    let len = 0;
    for (let i = 0; i < this.chunks.length; i++)
      len += this.chunks[i].length;
    let bytes = new Uint8Array(len);
    let offset = 0;
    for (let i = 0; i < this.chunks.length; i++) {
      bytes.set(this.chunks[i], offset);
      offset += this.chunks[i].length;
    }
    this.chunks = [];
    return bytes;
  }
  /**
   * Start a new fork for length-delimited data like a message
   * or a packed repeated field.
   *
   * Must be joined later with `join()`.
   */
  fork() {
    this.stack.push({ chunks: this.chunks, buf: this.buf });
    this.chunks = [];
    this.buf = [];
    return this;
  }
  /**
   * Join the last fork. Write its length and bytes, then
   * return to the previous state.
   */
  join() {
    let chunk = this.finish();
    let prev = this.stack.pop();
    if (!prev)
      throw new Error("invalid state, fork stack empty");
    this.chunks = prev.chunks;
    this.buf = prev.buf;
    this.uint32(chunk.byteLength);
    return this.raw(chunk);
  }
  /**
   * Writes a tag (field number and wire type).
   *
   * Equivalent to `uint32( (fieldNo << 3 | type) >>> 0 )`.
   *
   * Generated code should compute the tag ahead of time and call `uint32()`.
   */
  tag(fieldNo, type) {
    return this.uint32((fieldNo << 3 | type) >>> 0);
  }
  /**
   * Write a chunk of raw bytes.
   */
  raw(chunk) {
    if (this.buf.length) {
      this.chunks.push(new Uint8Array(this.buf));
      this.buf = [];
    }
    this.chunks.push(chunk);
    return this;
  }
  /**
   * Write a `uint32` value, an unsigned 32 bit varint.
   */
  uint32(value) {
    assertUInt32(value);
    while (value > 127) {
      this.buf.push(value & 127 | 128);
      value = value >>> 7;
    }
    this.buf.push(value);
    return this;
  }
  /**
   * Write a `int32` value, a signed 32 bit varint.
   */
  int32(value) {
    assertInt32(value);
    varint32write(value, this.buf);
    return this;
  }
  /**
   * Write a `bool` value, a varint.
   */
  bool(value) {
    this.buf.push(value ? 1 : 0);
    return this;
  }
  /**
   * Write a `bytes` value, length-delimited arbitrary data.
   */
  bytes(value) {
    this.uint32(value.byteLength);
    return this.raw(value);
  }
  /**
   * Write a `string` value, length-delimited data converted to UTF-8 text.
   */
  string(value) {
    let chunk = this.encodeUtf8(value);
    this.uint32(chunk.byteLength);
    return this.raw(chunk);
  }
  /**
   * Write a `float` value, 32-bit floating point number.
   */
  float(value) {
    assertFloat32(value);
    let chunk = new Uint8Array(4);
    new DataView(chunk.buffer).setFloat32(0, value, true);
    return this.raw(chunk);
  }
  /**
   * Write a `double` value, a 64-bit floating point number.
   */
  double(value) {
    let chunk = new Uint8Array(8);
    new DataView(chunk.buffer).setFloat64(0, value, true);
    return this.raw(chunk);
  }
  /**
   * Write a `fixed32` value, an unsigned, fixed-length 32-bit integer.
   */
  fixed32(value) {
    assertUInt32(value);
    let chunk = new Uint8Array(4);
    new DataView(chunk.buffer).setUint32(0, value, true);
    return this.raw(chunk);
  }
  /**
   * Write a `sfixed32` value, a signed, fixed-length 32-bit integer.
   */
  sfixed32(value) {
    assertInt32(value);
    let chunk = new Uint8Array(4);
    new DataView(chunk.buffer).setInt32(0, value, true);
    return this.raw(chunk);
  }
  /**
   * Write a `sint32` value, a signed, zigzag-encoded 32-bit varint.
   */
  sint32(value) {
    assertInt32(value);
    value = (value << 1 ^ value >> 31) >>> 0;
    varint32write(value, this.buf);
    return this;
  }
  /**
   * Write a `sfixed64` value, a signed, fixed-length 64-bit integer.
   */
  sfixed64(value) {
    let chunk = new Uint8Array(8), view = new DataView(chunk.buffer), tc = protoInt64.enc(value);
    view.setInt32(0, tc.lo, true);
    view.setInt32(4, tc.hi, true);
    return this.raw(chunk);
  }
  /**
   * Write a `fixed64` value, an unsigned, fixed-length 64 bit integer.
   */
  fixed64(value) {
    let chunk = new Uint8Array(8), view = new DataView(chunk.buffer), tc = protoInt64.uEnc(value);
    view.setInt32(0, tc.lo, true);
    view.setInt32(4, tc.hi, true);
    return this.raw(chunk);
  }
  /**
   * Write a `int64` value, a signed 64-bit varint.
   */
  int64(value) {
    let tc = protoInt64.enc(value);
    varint64write(tc.lo, tc.hi, this.buf);
    return this;
  }
  /**
   * Write a `sint64` value, a signed, zig-zag-encoded 64-bit varint.
   */
  sint64(value) {
    const tc = protoInt64.enc(value), sign = tc.hi >> 31, lo = tc.lo << 1 ^ sign, hi = (tc.hi << 1 | tc.lo >>> 31) ^ sign;
    varint64write(lo, hi, this.buf);
    return this;
  }
  /**
   * Write a `uint64` value, an unsigned 64-bit varint.
   */
  uint64(value) {
    const tc = protoInt64.uEnc(value);
    varint64write(tc.lo, tc.hi, this.buf);
    return this;
  }
};
var BinaryReader = class {
  constructor(buf, decodeUtf8 = getTextEncoding().decodeUtf8) {
    this.decodeUtf8 = decodeUtf8;
    this.varint64 = varint64read;
    this.uint32 = varint32read;
    this.buf = buf;
    this.len = buf.length;
    this.pos = 0;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  /**
   * Reads a tag - field number and wire type. Tags are uint32 varints; values
   * that do not fit in uint32 are rejected.
   */
  tag() {
    const start = this.pos;
    const tag = this.uint32();
    const bytesRead = this.pos - start;
    if (bytesRead > 5 || bytesRead == 5 && this.buf[this.pos - 1] > 15) {
      throw new Error("illegal tag: varint overflows uint32");
    }
    const fieldNo = tag >>> 3;
    const wireType = tag & 7;
    if (fieldNo <= 0 || wireType > 5) {
      throw new Error("illegal tag: field no " + fieldNo + " wire type " + wireType);
    }
    return [fieldNo, wireType];
  }
  /**
   * Skip one element and return the skipped data.
   *
   * When skipping StartGroup, provide the tags field number to check for
   * matching field number in the EndGroup tag.
   */
  skip(wireType, fieldNo) {
    let start = this.pos;
    switch (wireType) {
      case WireType.Varint:
        while (this.buf[this.pos++] & 128) {
        }
        break;
      // @ts-ignore TS7029: Fallthrough case in switch -- ignore instead of expect-error for compiler settings without noFallthroughCasesInSwitch: true
      case WireType.Bit64:
        this.pos += 4;
      case WireType.Bit32:
        this.pos += 4;
        break;
      case WireType.LengthDelimited:
        let len = this.uint32();
        this.pos += len;
        break;
      case WireType.StartGroup:
        for (; ; ) {
          const [fn, wt] = this.tag();
          if (wt === WireType.EndGroup) {
            if (fieldNo !== void 0 && fn !== fieldNo) {
              throw new Error("invalid end group tag");
            }
            break;
          }
          this.skip(wt, fn);
        }
        break;
      default:
        throw new Error("cant skip wire type " + wireType);
    }
    this.assertBounds();
    return this.buf.subarray(start, this.pos);
  }
  /**
   * Throws error if position in byte array is out of range.
   */
  assertBounds() {
    if (this.pos > this.len)
      throw new RangeError("premature EOF");
  }
  /**
   * Read a `int32` field, a signed 32 bit varint.
   */
  int32() {
    return this.uint32() | 0;
  }
  /**
   * Read a `sint32` field, a signed, zigzag-encoded 32-bit varint.
   */
  sint32() {
    let zze = this.uint32();
    return zze >>> 1 ^ -(zze & 1);
  }
  /**
   * Read a `int64` field, a signed 64-bit varint.
   */
  int64() {
    return protoInt64.dec(...this.varint64());
  }
  /**
   * Read a `uint64` field, an unsigned 64-bit varint.
   */
  uint64() {
    return protoInt64.uDec(...this.varint64());
  }
  /**
   * Read a `sint64` field, a signed, zig-zag-encoded 64-bit varint.
   */
  sint64() {
    let [lo, hi] = this.varint64();
    let s = -(lo & 1);
    lo = (lo >>> 1 | (hi & 1) << 31) ^ s;
    hi = hi >>> 1 ^ s;
    return protoInt64.dec(lo, hi);
  }
  /**
   * Read a `bool` field, a variant.
   */
  bool() {
    let [lo, hi] = this.varint64();
    return lo !== 0 || hi !== 0;
  }
  /**
   * Read a `fixed32` field, an unsigned, fixed-length 32-bit integer.
   */
  fixed32() {
    return this.view.getUint32((this.pos += 4) - 4, true);
  }
  /**
   * Read a `sfixed32` field, a signed, fixed-length 32-bit integer.
   */
  sfixed32() {
    return this.view.getInt32((this.pos += 4) - 4, true);
  }
  /**
   * Read a `fixed64` field, an unsigned, fixed-length 64 bit integer.
   */
  fixed64() {
    return protoInt64.uDec(this.sfixed32(), this.sfixed32());
  }
  /**
   * Read a `fixed64` field, a signed, fixed-length 64-bit integer.
   */
  sfixed64() {
    return protoInt64.dec(this.sfixed32(), this.sfixed32());
  }
  /**
   * Read a `float` field, 32-bit floating point number.
   */
  float() {
    return this.view.getFloat32((this.pos += 4) - 4, true);
  }
  /**
   * Read a `double` field, a 64-bit floating point number.
   */
  double() {
    return this.view.getFloat64((this.pos += 8) - 8, true);
  }
  /**
   * Read a `bytes` field, length-delimited arbitrary data.
   */
  bytes() {
    let len = this.uint32(), start = this.pos;
    this.pos += len;
    this.assertBounds();
    return this.buf.subarray(start, start + len);
  }
  /**
   * Read a `string` field, length-delimited data converted to UTF-8 text. If
   * `strict` is true, throw on invalid UTF-8 instead of substituting U+FFFD.
   */
  string(strict) {
    return this.decodeUtf8(this.bytes(), strict);
  }
};
function assertInt32(arg) {
  if (typeof arg == "string") {
    arg = Number(arg);
  } else if (typeof arg != "number") {
    throw new Error("invalid int32: " + typeof arg);
  }
  if (!Number.isInteger(arg) || arg > INT32_MAX || arg < INT32_MIN)
    throw new Error("invalid int32: " + arg);
}
function assertUInt32(arg) {
  if (typeof arg == "string") {
    arg = Number(arg);
  } else if (typeof arg != "number") {
    throw new Error("invalid uint32: " + typeof arg);
  }
  if (!Number.isInteger(arg) || arg > UINT32_MAX || arg < 0)
    throw new Error("invalid uint32: " + arg);
}
function assertFloat32(arg) {
  if (typeof arg == "string") {
    const o = arg;
    arg = Number(arg);
    if (Number.isNaN(arg) && o !== "NaN") {
      throw new Error("invalid float32: " + o);
    }
  } else if (typeof arg != "number") {
    throw new Error("invalid float32: " + typeof arg);
  }
  if (Number.isFinite(arg) && (arg > FLOAT32_MAX || arg < FLOAT32_MIN))
    throw new Error("invalid float32: " + arg);
}
function createBasePingRequest() {
  return {};
}
var PingRequest = {
  encode(_, writer = new BinaryWriter()) {
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBasePingRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(_) {
    return {};
  },
  toJSON(_) {
    const obj = {};
    return obj;
  },
  create(base) {
    return PingRequest.fromPartial(base ?? {});
  },
  fromPartial(_) {
    const message = createBasePingRequest();
    return message;
  }
};
function createBasePingResponse() {
  return { apiVersion: "", apiUptimeMs: 0, supervisorVersion: "", supervisorUptimeMs: 0 };
}
var PingResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.apiVersion !== "") {
      writer.uint32(10).string(message.apiVersion);
    }
    if (message.apiUptimeMs !== 0) {
      writer.uint32(16).uint64(message.apiUptimeMs);
    }
    if (message.supervisorVersion !== "") {
      writer.uint32(26).string(message.supervisorVersion);
    }
    if (message.supervisorUptimeMs !== 0) {
      writer.uint32(32).uint64(message.supervisorUptimeMs);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBasePingResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.apiVersion = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.apiUptimeMs = longToNumber(reader.uint64());
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.supervisorVersion = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.supervisorUptimeMs = longToNumber(reader.uint64());
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      apiVersion: isSet(object.apiVersion) ? globalThis.String(object.apiVersion) : isSet(object.api_version) ? globalThis.String(object.api_version) : "",
      apiUptimeMs: isSet(object.apiUptimeMs) ? globalThis.Number(object.apiUptimeMs) : isSet(object.api_uptime_ms) ? globalThis.Number(object.api_uptime_ms) : 0,
      supervisorVersion: isSet(object.supervisorVersion) ? globalThis.String(object.supervisorVersion) : isSet(object.supervisor_version) ? globalThis.String(object.supervisor_version) : "",
      supervisorUptimeMs: isSet(object.supervisorUptimeMs) ? globalThis.Number(object.supervisorUptimeMs) : isSet(object.supervisor_uptime_ms) ? globalThis.Number(object.supervisor_uptime_ms) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.apiVersion !== "") {
      obj.apiVersion = message.apiVersion;
    }
    if (message.apiUptimeMs !== 0) {
      obj.apiUptimeMs = Math.round(message.apiUptimeMs);
    }
    if (message.supervisorVersion !== "") {
      obj.supervisorVersion = message.supervisorVersion;
    }
    if (message.supervisorUptimeMs !== 0) {
      obj.supervisorUptimeMs = Math.round(message.supervisorUptimeMs);
    }
    return obj;
  },
  create(base) {
    return PingResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBasePingResponse();
    message.apiVersion = object.apiVersion ?? "";
    message.apiUptimeMs = object.apiUptimeMs ?? 0;
    message.supervisorVersion = object.supervisorVersion ?? "";
    message.supervisorUptimeMs = object.supervisorUptimeMs ?? 0;
    return message;
  }
};
function createBaseCreateWorkspaceRequest() {
  return {
    workspaceId: "",
    kernelImagePath: "",
    rootfsImagePath: "",
    rootfsReadOnly: false,
    vcpuCount: 0,
    memSizeMib: 0,
    guestVsockCid: 0,
    kernelBootArgs: void 0,
    network: void 0,
    tier: void 0
  };
}
var CreateWorkspaceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.kernelImagePath !== "") {
      writer.uint32(18).string(message.kernelImagePath);
    }
    if (message.rootfsImagePath !== "") {
      writer.uint32(26).string(message.rootfsImagePath);
    }
    if (message.rootfsReadOnly !== false) {
      writer.uint32(32).bool(message.rootfsReadOnly);
    }
    if (message.vcpuCount !== 0) {
      writer.uint32(40).uint32(message.vcpuCount);
    }
    if (message.memSizeMib !== 0) {
      writer.uint32(48).uint32(message.memSizeMib);
    }
    if (message.guestVsockCid !== 0) {
      writer.uint32(56).uint32(message.guestVsockCid);
    }
    if (message.kernelBootArgs !== void 0) {
      writer.uint32(66).string(message.kernelBootArgs);
    }
    if (message.network !== void 0) {
      NetworkConfig.encode(message.network, writer.uint32(74).fork()).join();
    }
    if (message.tier !== void 0) {
      writer.uint32(82).string(message.tier);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseCreateWorkspaceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.kernelImagePath = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.rootfsImagePath = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.rootfsReadOnly = reader.bool();
          continue;
        }
        case 5: {
          if (tag !== 40) {
            break;
          }
          message.vcpuCount = reader.uint32();
          continue;
        }
        case 6: {
          if (tag !== 48) {
            break;
          }
          message.memSizeMib = reader.uint32();
          continue;
        }
        case 7: {
          if (tag !== 56) {
            break;
          }
          message.guestVsockCid = reader.uint32();
          continue;
        }
        case 8: {
          if (tag !== 66) {
            break;
          }
          message.kernelBootArgs = reader.string();
          continue;
        }
        case 9: {
          if (tag !== 74) {
            break;
          }
          message.network = NetworkConfig.decode(reader, reader.uint32());
          continue;
        }
        case 10: {
          if (tag !== 82) {
            break;
          }
          message.tier = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      kernelImagePath: isSet(object.kernelImagePath) ? globalThis.String(object.kernelImagePath) : isSet(object.kernel_image_path) ? globalThis.String(object.kernel_image_path) : "",
      rootfsImagePath: isSet(object.rootfsImagePath) ? globalThis.String(object.rootfsImagePath) : isSet(object.rootfs_image_path) ? globalThis.String(object.rootfs_image_path) : "",
      rootfsReadOnly: isSet(object.rootfsReadOnly) ? globalThis.Boolean(object.rootfsReadOnly) : isSet(object.rootfs_read_only) ? globalThis.Boolean(object.rootfs_read_only) : false,
      vcpuCount: isSet(object.vcpuCount) ? globalThis.Number(object.vcpuCount) : isSet(object.vcpu_count) ? globalThis.Number(object.vcpu_count) : 0,
      memSizeMib: isSet(object.memSizeMib) ? globalThis.Number(object.memSizeMib) : isSet(object.mem_size_mib) ? globalThis.Number(object.mem_size_mib) : 0,
      guestVsockCid: isSet(object.guestVsockCid) ? globalThis.Number(object.guestVsockCid) : isSet(object.guest_vsock_cid) ? globalThis.Number(object.guest_vsock_cid) : 0,
      kernelBootArgs: isSet(object.kernelBootArgs) ? globalThis.String(object.kernelBootArgs) : isSet(object.kernel_boot_args) ? globalThis.String(object.kernel_boot_args) : void 0,
      network: isSet(object.network) ? NetworkConfig.fromJSON(object.network) : void 0,
      tier: isSet(object.tier) ? globalThis.String(object.tier) : void 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.kernelImagePath !== "") {
      obj.kernelImagePath = message.kernelImagePath;
    }
    if (message.rootfsImagePath !== "") {
      obj.rootfsImagePath = message.rootfsImagePath;
    }
    if (message.rootfsReadOnly !== false) {
      obj.rootfsReadOnly = message.rootfsReadOnly;
    }
    if (message.vcpuCount !== 0) {
      obj.vcpuCount = Math.round(message.vcpuCount);
    }
    if (message.memSizeMib !== 0) {
      obj.memSizeMib = Math.round(message.memSizeMib);
    }
    if (message.guestVsockCid !== 0) {
      obj.guestVsockCid = Math.round(message.guestVsockCid);
    }
    if (message.kernelBootArgs !== void 0) {
      obj.kernelBootArgs = message.kernelBootArgs;
    }
    if (message.network !== void 0) {
      obj.network = NetworkConfig.toJSON(message.network);
    }
    if (message.tier !== void 0) {
      obj.tier = message.tier;
    }
    return obj;
  },
  create(base) {
    return CreateWorkspaceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseCreateWorkspaceRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.kernelImagePath = object.kernelImagePath ?? "";
    message.rootfsImagePath = object.rootfsImagePath ?? "";
    message.rootfsReadOnly = object.rootfsReadOnly ?? false;
    message.vcpuCount = object.vcpuCount ?? 0;
    message.memSizeMib = object.memSizeMib ?? 0;
    message.guestVsockCid = object.guestVsockCid ?? 0;
    message.kernelBootArgs = object.kernelBootArgs ?? void 0;
    message.network = object.network !== void 0 && object.network !== null ? NetworkConfig.fromPartial(object.network) : void 0;
    message.tier = object.tier ?? void 0;
    return message;
  }
};
function createBaseNetworkConfig() {
  return { enableEgress: false, allowCidrs: [], allowHostnames: [], privacyRouter: void 0, exposedPorts: [] };
}
var NetworkConfig = {
  encode(message, writer = new BinaryWriter()) {
    if (message.enableEgress !== false) {
      writer.uint32(8).bool(message.enableEgress);
    }
    for (const v of message.allowCidrs) {
      writer.uint32(18).string(v);
    }
    for (const v of message.allowHostnames) {
      writer.uint32(26).string(v);
    }
    if (message.privacyRouter !== void 0) {
      PrivacyRouterConfig.encode(message.privacyRouter, writer.uint32(34).fork()).join();
    }
    for (const v of message.exposedPorts) {
      ExposedPort.encode(v, writer.uint32(42).fork()).join();
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseNetworkConfig();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 8) {
            break;
          }
          message.enableEgress = reader.bool();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.allowCidrs.push(reader.string());
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.allowHostnames.push(reader.string());
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.privacyRouter = PrivacyRouterConfig.decode(reader, reader.uint32());
          continue;
        }
        case 5: {
          if (tag !== 42) {
            break;
          }
          message.exposedPorts.push(ExposedPort.decode(reader, reader.uint32()));
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      enableEgress: isSet(object.enableEgress) ? globalThis.Boolean(object.enableEgress) : isSet(object.enable_egress) ? globalThis.Boolean(object.enable_egress) : false,
      allowCidrs: globalThis.Array.isArray(object?.allowCidrs) ? object.allowCidrs.map((e) => globalThis.String(e)) : globalThis.Array.isArray(object?.allow_cidrs) ? object.allow_cidrs.map((e) => globalThis.String(e)) : [],
      allowHostnames: globalThis.Array.isArray(object?.allowHostnames) ? object.allowHostnames.map((e) => globalThis.String(e)) : globalThis.Array.isArray(object?.allow_hostnames) ? object.allow_hostnames.map((e) => globalThis.String(e)) : [],
      privacyRouter: isSet(object.privacyRouter) ? PrivacyRouterConfig.fromJSON(object.privacyRouter) : isSet(object.privacy_router) ? PrivacyRouterConfig.fromJSON(object.privacy_router) : void 0,
      exposedPorts: globalThis.Array.isArray(object?.exposedPorts) ? object.exposedPorts.map((e) => ExposedPort.fromJSON(e)) : globalThis.Array.isArray(object?.exposed_ports) ? object.exposed_ports.map((e) => ExposedPort.fromJSON(e)) : []
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.enableEgress !== false) {
      obj.enableEgress = message.enableEgress;
    }
    if (message.allowCidrs?.length) {
      obj.allowCidrs = message.allowCidrs;
    }
    if (message.allowHostnames?.length) {
      obj.allowHostnames = message.allowHostnames;
    }
    if (message.privacyRouter !== void 0) {
      obj.privacyRouter = PrivacyRouterConfig.toJSON(message.privacyRouter);
    }
    if (message.exposedPorts?.length) {
      obj.exposedPorts = message.exposedPorts.map((e) => ExposedPort.toJSON(e));
    }
    return obj;
  },
  create(base) {
    return NetworkConfig.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseNetworkConfig();
    message.enableEgress = object.enableEgress ?? false;
    message.allowCidrs = object.allowCidrs?.map((e) => e) || [];
    message.allowHostnames = object.allowHostnames?.map((e) => e) || [];
    message.privacyRouter = object.privacyRouter !== void 0 && object.privacyRouter !== null ? PrivacyRouterConfig.fromPartial(object.privacyRouter) : void 0;
    message.exposedPorts = object.exposedPorts?.map((e) => ExposedPort.fromPartial(e)) || [];
    return message;
  }
};
function createBasePrivacyRouterConfig() {
  return {};
}
var PrivacyRouterConfig = {
  encode(_, writer = new BinaryWriter()) {
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBasePrivacyRouterConfig();
    while (reader.pos < end) {
      const tag = reader.uint32();
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(_) {
    return {};
  },
  toJSON(_) {
    const obj = {};
    return obj;
  },
  create(base) {
    return PrivacyRouterConfig.fromPartial(base ?? {});
  },
  fromPartial(_) {
    const message = createBasePrivacyRouterConfig();
    return message;
  }
};
function createBaseExposedPort() {
  return { port: 0, injectHeaders: [] };
}
var ExposedPort = {
  encode(message, writer = new BinaryWriter()) {
    if (message.port !== 0) {
      writer.uint32(8).uint32(message.port);
    }
    for (const v of message.injectHeaders) {
      HeaderInjection.encode(v, writer.uint32(18).fork()).join();
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseExposedPort();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 8) {
            break;
          }
          message.port = reader.uint32();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.injectHeaders.push(HeaderInjection.decode(reader, reader.uint32()));
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      port: isSet(object.port) ? globalThis.Number(object.port) : 0,
      injectHeaders: globalThis.Array.isArray(object?.injectHeaders) ? object.injectHeaders.map((e) => HeaderInjection.fromJSON(e)) : globalThis.Array.isArray(object?.inject_headers) ? object.inject_headers.map((e) => HeaderInjection.fromJSON(e)) : []
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.port !== 0) {
      obj.port = Math.round(message.port);
    }
    if (message.injectHeaders?.length) {
      obj.injectHeaders = message.injectHeaders.map((e) => HeaderInjection.toJSON(e));
    }
    return obj;
  },
  create(base) {
    return ExposedPort.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseExposedPort();
    message.port = object.port ?? 0;
    message.injectHeaders = object.injectHeaders?.map((e) => HeaderInjection.fromPartial(e)) || [];
    return message;
  }
};
function createBaseHeaderInjection() {
  return { name: "", value: "" };
}
var HeaderInjection = {
  encode(message, writer = new BinaryWriter()) {
    if (message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.value !== "") {
      writer.uint32(18).string(message.value);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseHeaderInjection();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.name = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.value = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      name: isSet(object.name) ? globalThis.String(object.name) : "",
      value: isSet(object.value) ? globalThis.String(object.value) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.name !== "") {
      obj.name = message.name;
    }
    if (message.value !== "") {
      obj.value = message.value;
    }
    return obj;
  },
  create(base) {
    return HeaderInjection.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseHeaderInjection();
    message.name = object.name ?? "";
    message.value = object.value ?? "";
    return message;
  }
};
function createBaseCreateWorkspaceResponse() {
  return { workspaceId: "", firecrackerPid: 0, vsockHostSocket: "", jailerChroot: "", network: void 0 };
}
var CreateWorkspaceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.firecrackerPid !== 0) {
      writer.uint32(16).uint32(message.firecrackerPid);
    }
    if (message.vsockHostSocket !== "") {
      writer.uint32(26).string(message.vsockHostSocket);
    }
    if (message.jailerChroot !== "") {
      writer.uint32(34).string(message.jailerChroot);
    }
    if (message.network !== void 0) {
      WorkspaceNetwork.encode(message.network, writer.uint32(42).fork()).join();
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseCreateWorkspaceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.firecrackerPid = reader.uint32();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.vsockHostSocket = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.jailerChroot = reader.string();
          continue;
        }
        case 5: {
          if (tag !== 42) {
            break;
          }
          message.network = WorkspaceNetwork.decode(reader, reader.uint32());
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      firecrackerPid: isSet(object.firecrackerPid) ? globalThis.Number(object.firecrackerPid) : isSet(object.firecracker_pid) ? globalThis.Number(object.firecracker_pid) : 0,
      vsockHostSocket: isSet(object.vsockHostSocket) ? globalThis.String(object.vsockHostSocket) : isSet(object.vsock_host_socket) ? globalThis.String(object.vsock_host_socket) : "",
      jailerChroot: isSet(object.jailerChroot) ? globalThis.String(object.jailerChroot) : isSet(object.jailer_chroot) ? globalThis.String(object.jailer_chroot) : "",
      network: isSet(object.network) ? WorkspaceNetwork.fromJSON(object.network) : void 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.firecrackerPid !== 0) {
      obj.firecrackerPid = Math.round(message.firecrackerPid);
    }
    if (message.vsockHostSocket !== "") {
      obj.vsockHostSocket = message.vsockHostSocket;
    }
    if (message.jailerChroot !== "") {
      obj.jailerChroot = message.jailerChroot;
    }
    if (message.network !== void 0) {
      obj.network = WorkspaceNetwork.toJSON(message.network);
    }
    return obj;
  },
  create(base) {
    return CreateWorkspaceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseCreateWorkspaceResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.firecrackerPid = object.firecrackerPid ?? 0;
    message.vsockHostSocket = object.vsockHostSocket ?? "";
    message.jailerChroot = object.jailerChroot ?? "";
    message.network = object.network !== void 0 && object.network !== null ? WorkspaceNetwork.fromPartial(object.network) : void 0;
    return message;
  }
};
function createBaseWorkspaceNetwork() {
  return { netnsPath: "", tapDevice: "", hostIp: "", guestIp: "", prefix: 0 };
}
var WorkspaceNetwork = {
  encode(message, writer = new BinaryWriter()) {
    if (message.netnsPath !== "") {
      writer.uint32(10).string(message.netnsPath);
    }
    if (message.tapDevice !== "") {
      writer.uint32(18).string(message.tapDevice);
    }
    if (message.hostIp !== "") {
      writer.uint32(26).string(message.hostIp);
    }
    if (message.guestIp !== "") {
      writer.uint32(34).string(message.guestIp);
    }
    if (message.prefix !== 0) {
      writer.uint32(40).uint32(message.prefix);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseWorkspaceNetwork();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.netnsPath = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.tapDevice = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.hostIp = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.guestIp = reader.string();
          continue;
        }
        case 5: {
          if (tag !== 40) {
            break;
          }
          message.prefix = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      netnsPath: isSet(object.netnsPath) ? globalThis.String(object.netnsPath) : isSet(object.netns_path) ? globalThis.String(object.netns_path) : "",
      tapDevice: isSet(object.tapDevice) ? globalThis.String(object.tapDevice) : isSet(object.tap_device) ? globalThis.String(object.tap_device) : "",
      hostIp: isSet(object.hostIp) ? globalThis.String(object.hostIp) : isSet(object.host_ip) ? globalThis.String(object.host_ip) : "",
      guestIp: isSet(object.guestIp) ? globalThis.String(object.guestIp) : isSet(object.guest_ip) ? globalThis.String(object.guest_ip) : "",
      prefix: isSet(object.prefix) ? globalThis.Number(object.prefix) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.netnsPath !== "") {
      obj.netnsPath = message.netnsPath;
    }
    if (message.tapDevice !== "") {
      obj.tapDevice = message.tapDevice;
    }
    if (message.hostIp !== "") {
      obj.hostIp = message.hostIp;
    }
    if (message.guestIp !== "") {
      obj.guestIp = message.guestIp;
    }
    if (message.prefix !== 0) {
      obj.prefix = Math.round(message.prefix);
    }
    return obj;
  },
  create(base) {
    return WorkspaceNetwork.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseWorkspaceNetwork();
    message.netnsPath = object.netnsPath ?? "";
    message.tapDevice = object.tapDevice ?? "";
    message.hostIp = object.hostIp ?? "";
    message.guestIp = object.guestIp ?? "";
    message.prefix = object.prefix ?? 0;
    return message;
  }
};
function createBaseDestroyWorkspaceRequest() {
  return { workspaceId: "", gracePeriodMs: 0 };
}
var DestroyWorkspaceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.gracePeriodMs !== 0) {
      writer.uint32(16).uint32(message.gracePeriodMs);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseDestroyWorkspaceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.gracePeriodMs = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      gracePeriodMs: isSet(object.gracePeriodMs) ? globalThis.Number(object.gracePeriodMs) : isSet(object.grace_period_ms) ? globalThis.Number(object.grace_period_ms) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.gracePeriodMs !== 0) {
      obj.gracePeriodMs = Math.round(message.gracePeriodMs);
    }
    return obj;
  },
  create(base) {
    return DestroyWorkspaceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseDestroyWorkspaceRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.gracePeriodMs = object.gracePeriodMs ?? 0;
    return message;
  }
};
function createBaseDestroyWorkspaceResponse() {
  return { workspaceId: "" };
}
var DestroyWorkspaceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseDestroyWorkspaceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    return obj;
  },
  create(base) {
    return DestroyWorkspaceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseDestroyWorkspaceResponse();
    message.workspaceId = object.workspaceId ?? "";
    return message;
  }
};
function createBaseExecuteCommandRequest() {
  return { workspaceId: "", command: "", args: [], timeoutMs: 0, guestPort: 0 };
}
var ExecuteCommandRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.command !== "") {
      writer.uint32(18).string(message.command);
    }
    for (const v of message.args) {
      writer.uint32(26).string(v);
    }
    if (message.timeoutMs !== 0) {
      writer.uint32(32).uint32(message.timeoutMs);
    }
    if (message.guestPort !== 0) {
      writer.uint32(40).uint32(message.guestPort);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseExecuteCommandRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.command = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.args.push(reader.string());
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.timeoutMs = reader.uint32();
          continue;
        }
        case 5: {
          if (tag !== 40) {
            break;
          }
          message.guestPort = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      command: isSet(object.command) ? globalThis.String(object.command) : "",
      args: globalThis.Array.isArray(object?.args) ? object.args.map((e) => globalThis.String(e)) : [],
      timeoutMs: isSet(object.timeoutMs) ? globalThis.Number(object.timeoutMs) : isSet(object.timeout_ms) ? globalThis.Number(object.timeout_ms) : 0,
      guestPort: isSet(object.guestPort) ? globalThis.Number(object.guestPort) : isSet(object.guest_port) ? globalThis.Number(object.guest_port) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.command !== "") {
      obj.command = message.command;
    }
    if (message.args?.length) {
      obj.args = message.args;
    }
    if (message.timeoutMs !== 0) {
      obj.timeoutMs = Math.round(message.timeoutMs);
    }
    if (message.guestPort !== 0) {
      obj.guestPort = Math.round(message.guestPort);
    }
    return obj;
  },
  create(base) {
    return ExecuteCommandRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseExecuteCommandRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.command = object.command ?? "";
    message.args = object.args?.map((e) => e) || [];
    message.timeoutMs = object.timeoutMs ?? 0;
    message.guestPort = object.guestPort ?? 0;
    return message;
  }
};
function createBaseExecuteCommandResponse() {
  return { workspaceId: "", stdout: "", stderr: "", exitCode: 0, elapsedMs: 0, truncated: false };
}
var ExecuteCommandResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.stdout !== "") {
      writer.uint32(18).string(message.stdout);
    }
    if (message.stderr !== "") {
      writer.uint32(26).string(message.stderr);
    }
    if (message.exitCode !== 0) {
      writer.uint32(32).int32(message.exitCode);
    }
    if (message.elapsedMs !== 0) {
      writer.uint32(40).uint64(message.elapsedMs);
    }
    if (message.truncated !== false) {
      writer.uint32(48).bool(message.truncated);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseExecuteCommandResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.stdout = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.stderr = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.exitCode = reader.int32();
          continue;
        }
        case 5: {
          if (tag !== 40) {
            break;
          }
          message.elapsedMs = longToNumber(reader.uint64());
          continue;
        }
        case 6: {
          if (tag !== 48) {
            break;
          }
          message.truncated = reader.bool();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      stdout: isSet(object.stdout) ? globalThis.String(object.stdout) : "",
      stderr: isSet(object.stderr) ? globalThis.String(object.stderr) : "",
      exitCode: isSet(object.exitCode) ? globalThis.Number(object.exitCode) : isSet(object.exit_code) ? globalThis.Number(object.exit_code) : 0,
      elapsedMs: isSet(object.elapsedMs) ? globalThis.Number(object.elapsedMs) : isSet(object.elapsed_ms) ? globalThis.Number(object.elapsed_ms) : 0,
      truncated: isSet(object.truncated) ? globalThis.Boolean(object.truncated) : false
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.stdout !== "") {
      obj.stdout = message.stdout;
    }
    if (message.stderr !== "") {
      obj.stderr = message.stderr;
    }
    if (message.exitCode !== 0) {
      obj.exitCode = Math.round(message.exitCode);
    }
    if (message.elapsedMs !== 0) {
      obj.elapsedMs = Math.round(message.elapsedMs);
    }
    if (message.truncated !== false) {
      obj.truncated = message.truncated;
    }
    return obj;
  },
  create(base) {
    return ExecuteCommandResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseExecuteCommandResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.stdout = object.stdout ?? "";
    message.stderr = object.stderr ?? "";
    message.exitCode = object.exitCode ?? 0;
    message.elapsedMs = object.elapsedMs ?? 0;
    message.truncated = object.truncated ?? false;
    return message;
  }
};
function createBaseListEventsRequest() {
  return { workspaceId: void 0, sinceChainIndex: 0, limit: 0 };
}
var ListEventsRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== void 0) {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.sinceChainIndex !== 0) {
      writer.uint32(16).uint64(message.sinceChainIndex);
    }
    if (message.limit !== 0) {
      writer.uint32(24).uint32(message.limit);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseListEventsRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.sinceChainIndex = longToNumber(reader.uint64());
          continue;
        }
        case 3: {
          if (tag !== 24) {
            break;
          }
          message.limit = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : void 0,
      sinceChainIndex: isSet(object.sinceChainIndex) ? globalThis.Number(object.sinceChainIndex) : isSet(object.since_chain_index) ? globalThis.Number(object.since_chain_index) : 0,
      limit: isSet(object.limit) ? globalThis.Number(object.limit) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== void 0) {
      obj.workspaceId = message.workspaceId;
    }
    if (message.sinceChainIndex !== 0) {
      obj.sinceChainIndex = Math.round(message.sinceChainIndex);
    }
    if (message.limit !== 0) {
      obj.limit = Math.round(message.limit);
    }
    return obj;
  },
  create(base) {
    return ListEventsRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseListEventsRequest();
    message.workspaceId = object.workspaceId ?? void 0;
    message.sinceChainIndex = object.sinceChainIndex ?? 0;
    message.limit = object.limit ?? 0;
    return message;
  }
};
function createBaseListEventsResponse() {
  return { events: [] };
}
var ListEventsResponse = {
  encode(message, writer = new BinaryWriter()) {
    for (const v of message.events) {
      AuditEvent.encode(v, writer.uint32(10).fork()).join();
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseListEventsResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.events.push(AuditEvent.decode(reader, reader.uint32()));
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      events: globalThis.Array.isArray(object?.events) ? object.events.map((e) => AuditEvent.fromJSON(e)) : []
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.events?.length) {
      obj.events = message.events.map((e) => AuditEvent.toJSON(e));
    }
    return obj;
  },
  create(base) {
    return ListEventsResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseListEventsResponse();
    message.events = object.events?.map((e) => AuditEvent.fromPartial(e)) || [];
    return message;
  }
};
function createBaseAuditEvent() {
  return {
    eventId: "",
    timestampMs: 0,
    eventType: "",
    workspaceId: void 0,
    payloadJson: "",
    chainIndex: 0,
    prevHashHex: "",
    signatureB64: "",
    signerPubkeyB64: ""
  };
}
var AuditEvent = {
  encode(message, writer = new BinaryWriter()) {
    if (message.eventId !== "") {
      writer.uint32(10).string(message.eventId);
    }
    if (message.timestampMs !== 0) {
      writer.uint32(16).uint64(message.timestampMs);
    }
    if (message.eventType !== "") {
      writer.uint32(26).string(message.eventType);
    }
    if (message.workspaceId !== void 0) {
      writer.uint32(34).string(message.workspaceId);
    }
    if (message.payloadJson !== "") {
      writer.uint32(42).string(message.payloadJson);
    }
    if (message.chainIndex !== 0) {
      writer.uint32(48).uint64(message.chainIndex);
    }
    if (message.prevHashHex !== "") {
      writer.uint32(58).string(message.prevHashHex);
    }
    if (message.signatureB64 !== "") {
      writer.uint32(66).string(message.signatureB64);
    }
    if (message.signerPubkeyB64 !== "") {
      writer.uint32(74).string(message.signerPubkeyB64);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseAuditEvent();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.eventId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.timestampMs = longToNumber(reader.uint64());
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.eventType = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 5: {
          if (tag !== 42) {
            break;
          }
          message.payloadJson = reader.string();
          continue;
        }
        case 6: {
          if (tag !== 48) {
            break;
          }
          message.chainIndex = longToNumber(reader.uint64());
          continue;
        }
        case 7: {
          if (tag !== 58) {
            break;
          }
          message.prevHashHex = reader.string();
          continue;
        }
        case 8: {
          if (tag !== 66) {
            break;
          }
          message.signatureB64 = reader.string();
          continue;
        }
        case 9: {
          if (tag !== 74) {
            break;
          }
          message.signerPubkeyB64 = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      eventId: isSet(object.eventId) ? globalThis.String(object.eventId) : isSet(object.event_id) ? globalThis.String(object.event_id) : "",
      timestampMs: isSet(object.timestampMs) ? globalThis.Number(object.timestampMs) : isSet(object.timestamp_ms) ? globalThis.Number(object.timestamp_ms) : 0,
      eventType: isSet(object.eventType) ? globalThis.String(object.eventType) : isSet(object.event_type) ? globalThis.String(object.event_type) : "",
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : void 0,
      payloadJson: isSet(object.payloadJson) ? globalThis.String(object.payloadJson) : isSet(object.payload_json) ? globalThis.String(object.payload_json) : "",
      chainIndex: isSet(object.chainIndex) ? globalThis.Number(object.chainIndex) : isSet(object.chain_index) ? globalThis.Number(object.chain_index) : 0,
      prevHashHex: isSet(object.prevHashHex) ? globalThis.String(object.prevHashHex) : isSet(object.prev_hash_hex) ? globalThis.String(object.prev_hash_hex) : "",
      signatureB64: isSet(object.signatureB64) ? globalThis.String(object.signatureB64) : isSet(object.signature_b64) ? globalThis.String(object.signature_b64) : "",
      signerPubkeyB64: isSet(object.signerPubkeyB64) ? globalThis.String(object.signerPubkeyB64) : isSet(object.signer_pubkey_b64) ? globalThis.String(object.signer_pubkey_b64) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.eventId !== "") {
      obj.eventId = message.eventId;
    }
    if (message.timestampMs !== 0) {
      obj.timestampMs = Math.round(message.timestampMs);
    }
    if (message.eventType !== "") {
      obj.eventType = message.eventType;
    }
    if (message.workspaceId !== void 0) {
      obj.workspaceId = message.workspaceId;
    }
    if (message.payloadJson !== "") {
      obj.payloadJson = message.payloadJson;
    }
    if (message.chainIndex !== 0) {
      obj.chainIndex = Math.round(message.chainIndex);
    }
    if (message.prevHashHex !== "") {
      obj.prevHashHex = message.prevHashHex;
    }
    if (message.signatureB64 !== "") {
      obj.signatureB64 = message.signatureB64;
    }
    if (message.signerPubkeyB64 !== "") {
      obj.signerPubkeyB64 = message.signerPubkeyB64;
    }
    return obj;
  },
  create(base) {
    return AuditEvent.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseAuditEvent();
    message.eventId = object.eventId ?? "";
    message.timestampMs = object.timestampMs ?? 0;
    message.eventType = object.eventType ?? "";
    message.workspaceId = object.workspaceId ?? void 0;
    message.payloadJson = object.payloadJson ?? "";
    message.chainIndex = object.chainIndex ?? 0;
    message.prevHashHex = object.prevHashHex ?? "";
    message.signatureB64 = object.signatureB64 ?? "";
    message.signerPubkeyB64 = object.signerPubkeyB64 ?? "";
    return message;
  }
};
function createBaseWriteFileRequest() {
  return { workspaceId: "", path: "", content: new Uint8Array(0), guestPort: 0 };
}
var WriteFileRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.path !== "") {
      writer.uint32(18).string(message.path);
    }
    if (message.content.length !== 0) {
      writer.uint32(26).bytes(message.content);
    }
    if (message.guestPort !== 0) {
      writer.uint32(32).uint32(message.guestPort);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseWriteFileRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.path = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.content = reader.bytes();
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.guestPort = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      path: isSet(object.path) ? globalThis.String(object.path) : "",
      content: isSet(object.content) ? bytesFromBase64(object.content) : new Uint8Array(0),
      guestPort: isSet(object.guestPort) ? globalThis.Number(object.guestPort) : isSet(object.guest_port) ? globalThis.Number(object.guest_port) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.path !== "") {
      obj.path = message.path;
    }
    if (message.content.length !== 0) {
      obj.content = base64FromBytes(message.content);
    }
    if (message.guestPort !== 0) {
      obj.guestPort = Math.round(message.guestPort);
    }
    return obj;
  },
  create(base) {
    return WriteFileRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseWriteFileRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.path = object.path ?? "";
    message.content = object.content ?? new Uint8Array(0);
    message.guestPort = object.guestPort ?? 0;
    return message;
  }
};
function createBaseWriteFileResponse() {
  return { workspaceId: "", bytesWritten: 0, absolutePath: "" };
}
var WriteFileResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.bytesWritten !== 0) {
      writer.uint32(16).uint64(message.bytesWritten);
    }
    if (message.absolutePath !== "") {
      writer.uint32(26).string(message.absolutePath);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseWriteFileResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.bytesWritten = longToNumber(reader.uint64());
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.absolutePath = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      bytesWritten: isSet(object.bytesWritten) ? globalThis.Number(object.bytesWritten) : isSet(object.bytes_written) ? globalThis.Number(object.bytes_written) : 0,
      absolutePath: isSet(object.absolutePath) ? globalThis.String(object.absolutePath) : isSet(object.absolute_path) ? globalThis.String(object.absolute_path) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.bytesWritten !== 0) {
      obj.bytesWritten = Math.round(message.bytesWritten);
    }
    if (message.absolutePath !== "") {
      obj.absolutePath = message.absolutePath;
    }
    return obj;
  },
  create(base) {
    return WriteFileResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseWriteFileResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.bytesWritten = object.bytesWritten ?? 0;
    message.absolutePath = object.absolutePath ?? "";
    return message;
  }
};
function createBaseReadFileRequest() {
  return { workspaceId: "", path: "", maxBytes: 0, guestPort: 0 };
}
var ReadFileRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.path !== "") {
      writer.uint32(18).string(message.path);
    }
    if (message.maxBytes !== 0) {
      writer.uint32(24).uint64(message.maxBytes);
    }
    if (message.guestPort !== 0) {
      writer.uint32(32).uint32(message.guestPort);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseReadFileRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.path = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 24) {
            break;
          }
          message.maxBytes = longToNumber(reader.uint64());
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.guestPort = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      path: isSet(object.path) ? globalThis.String(object.path) : "",
      maxBytes: isSet(object.maxBytes) ? globalThis.Number(object.maxBytes) : isSet(object.max_bytes) ? globalThis.Number(object.max_bytes) : 0,
      guestPort: isSet(object.guestPort) ? globalThis.Number(object.guestPort) : isSet(object.guest_port) ? globalThis.Number(object.guest_port) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.path !== "") {
      obj.path = message.path;
    }
    if (message.maxBytes !== 0) {
      obj.maxBytes = Math.round(message.maxBytes);
    }
    if (message.guestPort !== 0) {
      obj.guestPort = Math.round(message.guestPort);
    }
    return obj;
  },
  create(base) {
    return ReadFileRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseReadFileRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.path = object.path ?? "";
    message.maxBytes = object.maxBytes ?? 0;
    message.guestPort = object.guestPort ?? 0;
    return message;
  }
};
function createBaseReadFileResponse() {
  return { workspaceId: "", content: new Uint8Array(0), sizeBytes: 0, truncated: false };
}
var ReadFileResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.content.length !== 0) {
      writer.uint32(18).bytes(message.content);
    }
    if (message.sizeBytes !== 0) {
      writer.uint32(24).uint64(message.sizeBytes);
    }
    if (message.truncated !== false) {
      writer.uint32(32).bool(message.truncated);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseReadFileResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.content = reader.bytes();
          continue;
        }
        case 3: {
          if (tag !== 24) {
            break;
          }
          message.sizeBytes = longToNumber(reader.uint64());
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.truncated = reader.bool();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      content: isSet(object.content) ? bytesFromBase64(object.content) : new Uint8Array(0),
      sizeBytes: isSet(object.sizeBytes) ? globalThis.Number(object.sizeBytes) : isSet(object.size_bytes) ? globalThis.Number(object.size_bytes) : 0,
      truncated: isSet(object.truncated) ? globalThis.Boolean(object.truncated) : false
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.content.length !== 0) {
      obj.content = base64FromBytes(message.content);
    }
    if (message.sizeBytes !== 0) {
      obj.sizeBytes = Math.round(message.sizeBytes);
    }
    if (message.truncated !== false) {
      obj.truncated = message.truncated;
    }
    return obj;
  },
  create(base) {
    return ReadFileResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseReadFileResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.content = object.content ?? new Uint8Array(0);
    message.sizeBytes = object.sizeBytes ?? 0;
    message.truncated = object.truncated ?? false;
    return message;
  }
};
function createBasePauseWorkspaceRequest() {
  return { workspaceId: "" };
}
var PauseWorkspaceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBasePauseWorkspaceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    return obj;
  },
  create(base) {
    return PauseWorkspaceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBasePauseWorkspaceRequest();
    message.workspaceId = object.workspaceId ?? "";
    return message;
  }
};
function createBasePauseWorkspaceResponse() {
  return { workspaceId: "" };
}
var PauseWorkspaceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBasePauseWorkspaceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    return obj;
  },
  create(base) {
    return PauseWorkspaceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBasePauseWorkspaceResponse();
    message.workspaceId = object.workspaceId ?? "";
    return message;
  }
};
function createBaseResumeWorkspaceRequest() {
  return { workspaceId: "" };
}
var ResumeWorkspaceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseResumeWorkspaceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    return obj;
  },
  create(base) {
    return ResumeWorkspaceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseResumeWorkspaceRequest();
    message.workspaceId = object.workspaceId ?? "";
    return message;
  }
};
function createBaseResumeWorkspaceResponse() {
  return { workspaceId: "" };
}
var ResumeWorkspaceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseResumeWorkspaceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    return obj;
  },
  create(base) {
    return ResumeWorkspaceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseResumeWorkspaceResponse();
    message.workspaceId = object.workspaceId ?? "";
    return message;
  }
};
function createBaseSnapshotWorkspaceRequest() {
  return { workspaceId: "", live: false };
}
var SnapshotWorkspaceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.live !== false) {
      writer.uint32(16).bool(message.live);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseSnapshotWorkspaceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.live = reader.bool();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      live: isSet(object.live) ? globalThis.Boolean(object.live) : false
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.live !== false) {
      obj.live = message.live;
    }
    return obj;
  },
  create(base) {
    return SnapshotWorkspaceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseSnapshotWorkspaceRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.live = object.live ?? false;
    return message;
  }
};
function createBaseSnapshotWorkspaceResponse() {
  return {
    snapshotId: "",
    createdFromWorkspaceId: "",
    memSha256: "",
    vmstateSha256: "",
    sizeBytes: 0,
    firecrackerPid: void 0
  };
}
var SnapshotWorkspaceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.snapshotId !== "") {
      writer.uint32(10).string(message.snapshotId);
    }
    if (message.createdFromWorkspaceId !== "") {
      writer.uint32(18).string(message.createdFromWorkspaceId);
    }
    if (message.memSha256 !== "") {
      writer.uint32(26).string(message.memSha256);
    }
    if (message.vmstateSha256 !== "") {
      writer.uint32(34).string(message.vmstateSha256);
    }
    if (message.sizeBytes !== 0) {
      writer.uint32(40).uint64(message.sizeBytes);
    }
    if (message.firecrackerPid !== void 0) {
      writer.uint32(48).uint32(message.firecrackerPid);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseSnapshotWorkspaceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.snapshotId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.createdFromWorkspaceId = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.memSha256 = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.vmstateSha256 = reader.string();
          continue;
        }
        case 5: {
          if (tag !== 40) {
            break;
          }
          message.sizeBytes = longToNumber(reader.uint64());
          continue;
        }
        case 6: {
          if (tag !== 48) {
            break;
          }
          message.firecrackerPid = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      snapshotId: isSet(object.snapshotId) ? globalThis.String(object.snapshotId) : isSet(object.snapshot_id) ? globalThis.String(object.snapshot_id) : "",
      createdFromWorkspaceId: isSet(object.createdFromWorkspaceId) ? globalThis.String(object.createdFromWorkspaceId) : isSet(object.created_from_workspace_id) ? globalThis.String(object.created_from_workspace_id) : "",
      memSha256: isSet(object.memSha256) ? globalThis.String(object.memSha256) : isSet(object.mem_sha256) ? globalThis.String(object.mem_sha256) : "",
      vmstateSha256: isSet(object.vmstateSha256) ? globalThis.String(object.vmstateSha256) : isSet(object.vmstate_sha256) ? globalThis.String(object.vmstate_sha256) : "",
      sizeBytes: isSet(object.sizeBytes) ? globalThis.Number(object.sizeBytes) : isSet(object.size_bytes) ? globalThis.Number(object.size_bytes) : 0,
      firecrackerPid: isSet(object.firecrackerPid) ? globalThis.Number(object.firecrackerPid) : isSet(object.firecracker_pid) ? globalThis.Number(object.firecracker_pid) : void 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.snapshotId !== "") {
      obj.snapshotId = message.snapshotId;
    }
    if (message.createdFromWorkspaceId !== "") {
      obj.createdFromWorkspaceId = message.createdFromWorkspaceId;
    }
    if (message.memSha256 !== "") {
      obj.memSha256 = message.memSha256;
    }
    if (message.vmstateSha256 !== "") {
      obj.vmstateSha256 = message.vmstateSha256;
    }
    if (message.sizeBytes !== 0) {
      obj.sizeBytes = Math.round(message.sizeBytes);
    }
    if (message.firecrackerPid !== void 0) {
      obj.firecrackerPid = Math.round(message.firecrackerPid);
    }
    return obj;
  },
  create(base) {
    return SnapshotWorkspaceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseSnapshotWorkspaceResponse();
    message.snapshotId = object.snapshotId ?? "";
    message.createdFromWorkspaceId = object.createdFromWorkspaceId ?? "";
    message.memSha256 = object.memSha256 ?? "";
    message.vmstateSha256 = object.vmstateSha256 ?? "";
    message.sizeBytes = object.sizeBytes ?? 0;
    message.firecrackerPid = object.firecrackerPid ?? void 0;
    return message;
  }
};
function createBaseRestoreWorkspaceRequest() {
  return { snapshotId: "", newWorkspaceId: "" };
}
var RestoreWorkspaceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.snapshotId !== "") {
      writer.uint32(10).string(message.snapshotId);
    }
    if (message.newWorkspaceId !== "") {
      writer.uint32(18).string(message.newWorkspaceId);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseRestoreWorkspaceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.snapshotId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.newWorkspaceId = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      snapshotId: isSet(object.snapshotId) ? globalThis.String(object.snapshotId) : isSet(object.snapshot_id) ? globalThis.String(object.snapshot_id) : "",
      newWorkspaceId: isSet(object.newWorkspaceId) ? globalThis.String(object.newWorkspaceId) : isSet(object.new_workspace_id) ? globalThis.String(object.new_workspace_id) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.snapshotId !== "") {
      obj.snapshotId = message.snapshotId;
    }
    if (message.newWorkspaceId !== "") {
      obj.newWorkspaceId = message.newWorkspaceId;
    }
    return obj;
  },
  create(base) {
    return RestoreWorkspaceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseRestoreWorkspaceRequest();
    message.snapshotId = object.snapshotId ?? "";
    message.newWorkspaceId = object.newWorkspaceId ?? "";
    return message;
  }
};
function createBaseRestoreWorkspaceResponse() {
  return { workspaceId: "", firecrackerPid: 0, vsockHostSocket: "", jailerChroot: "" };
}
var RestoreWorkspaceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.firecrackerPid !== 0) {
      writer.uint32(16).uint32(message.firecrackerPid);
    }
    if (message.vsockHostSocket !== "") {
      writer.uint32(26).string(message.vsockHostSocket);
    }
    if (message.jailerChroot !== "") {
      writer.uint32(34).string(message.jailerChroot);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseRestoreWorkspaceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.firecrackerPid = reader.uint32();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.vsockHostSocket = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.jailerChroot = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      firecrackerPid: isSet(object.firecrackerPid) ? globalThis.Number(object.firecrackerPid) : isSet(object.firecracker_pid) ? globalThis.Number(object.firecracker_pid) : 0,
      vsockHostSocket: isSet(object.vsockHostSocket) ? globalThis.String(object.vsockHostSocket) : isSet(object.vsock_host_socket) ? globalThis.String(object.vsock_host_socket) : "",
      jailerChroot: isSet(object.jailerChroot) ? globalThis.String(object.jailerChroot) : isSet(object.jailer_chroot) ? globalThis.String(object.jailer_chroot) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.firecrackerPid !== 0) {
      obj.firecrackerPid = Math.round(message.firecrackerPid);
    }
    if (message.vsockHostSocket !== "") {
      obj.vsockHostSocket = message.vsockHostSocket;
    }
    if (message.jailerChroot !== "") {
      obj.jailerChroot = message.jailerChroot;
    }
    return obj;
  },
  create(base) {
    return RestoreWorkspaceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseRestoreWorkspaceResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.firecrackerPid = object.firecrackerPid ?? 0;
    message.vsockHostSocket = object.vsockHostSocket ?? "";
    message.jailerChroot = object.jailerChroot ?? "";
    return message;
  }
};
function createBaseForkWorkspaceRequest() {
  return { snapshotId: "", newWorkspaceId: "", hostname: "" };
}
var ForkWorkspaceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.snapshotId !== "") {
      writer.uint32(10).string(message.snapshotId);
    }
    if (message.newWorkspaceId !== "") {
      writer.uint32(18).string(message.newWorkspaceId);
    }
    if (message.hostname !== "") {
      writer.uint32(26).string(message.hostname);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseForkWorkspaceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.snapshotId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.newWorkspaceId = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.hostname = reader.string();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      snapshotId: isSet(object.snapshotId) ? globalThis.String(object.snapshotId) : isSet(object.snapshot_id) ? globalThis.String(object.snapshot_id) : "",
      newWorkspaceId: isSet(object.newWorkspaceId) ? globalThis.String(object.newWorkspaceId) : isSet(object.new_workspace_id) ? globalThis.String(object.new_workspace_id) : "",
      hostname: isSet(object.hostname) ? globalThis.String(object.hostname) : ""
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.snapshotId !== "") {
      obj.snapshotId = message.snapshotId;
    }
    if (message.newWorkspaceId !== "") {
      obj.newWorkspaceId = message.newWorkspaceId;
    }
    if (message.hostname !== "") {
      obj.hostname = message.hostname;
    }
    return obj;
  },
  create(base) {
    return ForkWorkspaceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseForkWorkspaceRequest();
    message.snapshotId = object.snapshotId ?? "";
    message.newWorkspaceId = object.newWorkspaceId ?? "";
    message.hostname = object.hostname ?? "";
    return message;
  }
};
function createBaseForkWorkspaceResponse() {
  return {
    workspaceId: "",
    firecrackerPid: 0,
    vsockHostSocket: "",
    jailerChroot: "",
    sourceSnapshotId: "",
    hostname: "",
    machineId: "",
    guestVsockCid: 0
  };
}
var ForkWorkspaceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.firecrackerPid !== 0) {
      writer.uint32(16).uint32(message.firecrackerPid);
    }
    if (message.vsockHostSocket !== "") {
      writer.uint32(26).string(message.vsockHostSocket);
    }
    if (message.jailerChroot !== "") {
      writer.uint32(34).string(message.jailerChroot);
    }
    if (message.sourceSnapshotId !== "") {
      writer.uint32(42).string(message.sourceSnapshotId);
    }
    if (message.hostname !== "") {
      writer.uint32(50).string(message.hostname);
    }
    if (message.machineId !== "") {
      writer.uint32(58).string(message.machineId);
    }
    if (message.guestVsockCid !== 0) {
      writer.uint32(64).uint32(message.guestVsockCid);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseForkWorkspaceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.firecrackerPid = reader.uint32();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.vsockHostSocket = reader.string();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.jailerChroot = reader.string();
          continue;
        }
        case 5: {
          if (tag !== 42) {
            break;
          }
          message.sourceSnapshotId = reader.string();
          continue;
        }
        case 6: {
          if (tag !== 50) {
            break;
          }
          message.hostname = reader.string();
          continue;
        }
        case 7: {
          if (tag !== 58) {
            break;
          }
          message.machineId = reader.string();
          continue;
        }
        case 8: {
          if (tag !== 64) {
            break;
          }
          message.guestVsockCid = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      firecrackerPid: isSet(object.firecrackerPid) ? globalThis.Number(object.firecrackerPid) : isSet(object.firecracker_pid) ? globalThis.Number(object.firecracker_pid) : 0,
      vsockHostSocket: isSet(object.vsockHostSocket) ? globalThis.String(object.vsockHostSocket) : isSet(object.vsock_host_socket) ? globalThis.String(object.vsock_host_socket) : "",
      jailerChroot: isSet(object.jailerChroot) ? globalThis.String(object.jailerChroot) : isSet(object.jailer_chroot) ? globalThis.String(object.jailer_chroot) : "",
      sourceSnapshotId: isSet(object.sourceSnapshotId) ? globalThis.String(object.sourceSnapshotId) : isSet(object.source_snapshot_id) ? globalThis.String(object.source_snapshot_id) : "",
      hostname: isSet(object.hostname) ? globalThis.String(object.hostname) : "",
      machineId: isSet(object.machineId) ? globalThis.String(object.machineId) : isSet(object.machine_id) ? globalThis.String(object.machine_id) : "",
      guestVsockCid: isSet(object.guestVsockCid) ? globalThis.Number(object.guestVsockCid) : isSet(object.guest_vsock_cid) ? globalThis.Number(object.guest_vsock_cid) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.firecrackerPid !== 0) {
      obj.firecrackerPid = Math.round(message.firecrackerPid);
    }
    if (message.vsockHostSocket !== "") {
      obj.vsockHostSocket = message.vsockHostSocket;
    }
    if (message.jailerChroot !== "") {
      obj.jailerChroot = message.jailerChroot;
    }
    if (message.sourceSnapshotId !== "") {
      obj.sourceSnapshotId = message.sourceSnapshotId;
    }
    if (message.hostname !== "") {
      obj.hostname = message.hostname;
    }
    if (message.machineId !== "") {
      obj.machineId = message.machineId;
    }
    if (message.guestVsockCid !== 0) {
      obj.guestVsockCid = Math.round(message.guestVsockCid);
    }
    return obj;
  },
  create(base) {
    return ForkWorkspaceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseForkWorkspaceResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.firecrackerPid = object.firecrackerPid ?? 0;
    message.vsockHostSocket = object.vsockHostSocket ?? "";
    message.jailerChroot = object.jailerChroot ?? "";
    message.sourceSnapshotId = object.sourceSnapshotId ?? "";
    message.hostname = object.hostname ?? "";
    message.machineId = object.machineId ?? "";
    message.guestVsockCid = object.guestVsockCid ?? 0;
    return message;
  }
};
function createBaseGetPoolStatusRequest() {
  return {};
}
var GetPoolStatusRequest = {
  encode(_, writer = new BinaryWriter()) {
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseGetPoolStatusRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(_) {
    return {};
  },
  toJSON(_) {
    const obj = {};
    return obj;
  },
  create(base) {
    return GetPoolStatusRequest.fromPartial(base ?? {});
  },
  fromPartial(_) {
    const message = createBaseGetPoolStatusRequest();
    return message;
  }
};
function createBaseGetPoolStatusResponse() {
  return { configured: false, tier: "", targetSize: 0, available: 0, inFlight: 0 };
}
var GetPoolStatusResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.configured !== false) {
      writer.uint32(8).bool(message.configured);
    }
    if (message.tier !== "") {
      writer.uint32(18).string(message.tier);
    }
    if (message.targetSize !== 0) {
      writer.uint32(24).uint32(message.targetSize);
    }
    if (message.available !== 0) {
      writer.uint32(32).uint32(message.available);
    }
    if (message.inFlight !== 0) {
      writer.uint32(40).uint32(message.inFlight);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseGetPoolStatusResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 8) {
            break;
          }
          message.configured = reader.bool();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.tier = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 24) {
            break;
          }
          message.targetSize = reader.uint32();
          continue;
        }
        case 4: {
          if (tag !== 32) {
            break;
          }
          message.available = reader.uint32();
          continue;
        }
        case 5: {
          if (tag !== 40) {
            break;
          }
          message.inFlight = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      configured: isSet(object.configured) ? globalThis.Boolean(object.configured) : false,
      tier: isSet(object.tier) ? globalThis.String(object.tier) : "",
      targetSize: isSet(object.targetSize) ? globalThis.Number(object.targetSize) : isSet(object.target_size) ? globalThis.Number(object.target_size) : 0,
      available: isSet(object.available) ? globalThis.Number(object.available) : 0,
      inFlight: isSet(object.inFlight) ? globalThis.Number(object.inFlight) : isSet(object.in_flight) ? globalThis.Number(object.in_flight) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.configured !== false) {
      obj.configured = message.configured;
    }
    if (message.tier !== "") {
      obj.tier = message.tier;
    }
    if (message.targetSize !== 0) {
      obj.targetSize = Math.round(message.targetSize);
    }
    if (message.available !== 0) {
      obj.available = Math.round(message.available);
    }
    if (message.inFlight !== 0) {
      obj.inFlight = Math.round(message.inFlight);
    }
    return obj;
  },
  create(base) {
    return GetPoolStatusResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseGetPoolStatusResponse();
    message.configured = object.configured ?? false;
    message.tier = object.tier ?? "";
    message.targetSize = object.targetSize ?? 0;
    message.available = object.available ?? 0;
    message.inFlight = object.inFlight ?? 0;
    return message;
  }
};
function createBaseExposePortRequest() {
  return { workspaceId: "", port: void 0 };
}
var ExposePortRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.port !== void 0) {
      ExposedPort.encode(message.port, writer.uint32(18).fork()).join();
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseExposePortRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.port = ExposedPort.decode(reader, reader.uint32());
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      port: isSet(object.port) ? ExposedPort.fromJSON(object.port) : void 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.port !== void 0) {
      obj.port = ExposedPort.toJSON(message.port);
    }
    return obj;
  },
  create(base) {
    return ExposePortRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseExposePortRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.port = object.port !== void 0 && object.port !== null ? ExposedPort.fromPartial(object.port) : void 0;
    return message;
  }
};
function createBaseExposePortResponse() {
  return { workspaceId: "", port: 0 };
}
var ExposePortResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.port !== 0) {
      writer.uint32(16).uint32(message.port);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseExposePortResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.port = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      port: isSet(object.port) ? globalThis.Number(object.port) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.port !== 0) {
      obj.port = Math.round(message.port);
    }
    return obj;
  },
  create(base) {
    return ExposePortResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseExposePortResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.port = object.port ?? 0;
    return message;
  }
};
function createBaseUnexposePortRequest() {
  return { workspaceId: "", port: 0 };
}
var UnexposePortRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.port !== 0) {
      writer.uint32(16).uint32(message.port);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseUnexposePortRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.port = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      port: isSet(object.port) ? globalThis.Number(object.port) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.port !== 0) {
      obj.port = Math.round(message.port);
    }
    return obj;
  },
  create(base) {
    return UnexposePortRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseUnexposePortRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.port = object.port ?? 0;
    return message;
  }
};
function createBaseUnexposePortResponse() {
  return { workspaceId: "", port: 0 };
}
var UnexposePortResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.port !== 0) {
      writer.uint32(16).uint32(message.port);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseUnexposePortResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 16) {
            break;
          }
          message.port = reader.uint32();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      port: isSet(object.port) ? globalThis.Number(object.port) : 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.port !== 0) {
      obj.port = Math.round(message.port);
    }
    return obj;
  },
  create(base) {
    return UnexposePortResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseUnexposePortResponse();
    message.workspaceId = object.workspaceId ?? "";
    message.port = object.port ?? 0;
    return message;
  }
};
function createBaseGetAttestationEvidenceRequest() {
  return { workspaceId: "", nonce: new Uint8Array(0) };
}
var GetAttestationEvidenceRequest = {
  encode(message, writer = new BinaryWriter()) {
    if (message.workspaceId !== "") {
      writer.uint32(10).string(message.workspaceId);
    }
    if (message.nonce.length !== 0) {
      writer.uint32(18).bytes(message.nonce);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseGetAttestationEvidenceRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.nonce = reader.bytes();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      nonce: isSet(object.nonce) ? bytesFromBase64(object.nonce) : new Uint8Array(0)
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.nonce.length !== 0) {
      obj.nonce = base64FromBytes(message.nonce);
    }
    return obj;
  },
  create(base) {
    return GetAttestationEvidenceRequest.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseGetAttestationEvidenceRequest();
    message.workspaceId = object.workspaceId ?? "";
    message.nonce = object.nonce ?? new Uint8Array(0);
    return message;
  }
};
function createBaseGetAttestationEvidenceResponse() {
  return { evidence: void 0 };
}
var GetAttestationEvidenceResponse = {
  encode(message, writer = new BinaryWriter()) {
    if (message.evidence !== void 0) {
      AttestationEvidence.encode(message.evidence, writer.uint32(10).fork()).join();
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseGetAttestationEvidenceResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.evidence = AttestationEvidence.decode(reader, reader.uint32());
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return { evidence: isSet(object.evidence) ? AttestationEvidence.fromJSON(object.evidence) : void 0 };
  },
  toJSON(message) {
    const obj = {};
    if (message.evidence !== void 0) {
      obj.evidence = AttestationEvidence.toJSON(message.evidence);
    }
    return obj;
  },
  create(base) {
    return GetAttestationEvidenceResponse.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseGetAttestationEvidenceResponse();
    message.evidence = object.evidence !== void 0 && object.evidence !== null ? AttestationEvidence.fromPartial(object.evidence) : void 0;
    return message;
  }
};
function createBaseAttestationEvidence() {
  return {
    providerType: "",
    workspaceId: "",
    measurement: new Uint8Array(0),
    nonce: new Uint8Array(0),
    issuedAt: 0,
    reportData: new Uint8Array(0),
    proof: void 0
  };
}
var AttestationEvidence = {
  encode(message, writer = new BinaryWriter()) {
    if (message.providerType !== "") {
      writer.uint32(10).string(message.providerType);
    }
    if (message.workspaceId !== "") {
      writer.uint32(18).string(message.workspaceId);
    }
    if (message.measurement.length !== 0) {
      writer.uint32(26).bytes(message.measurement);
    }
    if (message.nonce.length !== 0) {
      writer.uint32(34).bytes(message.nonce);
    }
    if (message.issuedAt !== 0) {
      writer.uint32(40).int64(message.issuedAt);
    }
    if (message.reportData.length !== 0) {
      writer.uint32(50).bytes(message.reportData);
    }
    if (message.proof !== void 0) {
      AttestationProof.encode(message.proof, writer.uint32(58).fork()).join();
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseAttestationEvidence();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.providerType = reader.string();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.workspaceId = reader.string();
          continue;
        }
        case 3: {
          if (tag !== 26) {
            break;
          }
          message.measurement = reader.bytes();
          continue;
        }
        case 4: {
          if (tag !== 34) {
            break;
          }
          message.nonce = reader.bytes();
          continue;
        }
        case 5: {
          if (tag !== 40) {
            break;
          }
          message.issuedAt = longToNumber(reader.int64());
          continue;
        }
        case 6: {
          if (tag !== 50) {
            break;
          }
          message.reportData = reader.bytes();
          continue;
        }
        case 7: {
          if (tag !== 58) {
            break;
          }
          message.proof = AttestationProof.decode(reader, reader.uint32());
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      providerType: isSet(object.providerType) ? globalThis.String(object.providerType) : isSet(object.provider_type) ? globalThis.String(object.provider_type) : "",
      workspaceId: isSet(object.workspaceId) ? globalThis.String(object.workspaceId) : isSet(object.workspace_id) ? globalThis.String(object.workspace_id) : "",
      measurement: isSet(object.measurement) ? bytesFromBase64(object.measurement) : new Uint8Array(0),
      nonce: isSet(object.nonce) ? bytesFromBase64(object.nonce) : new Uint8Array(0),
      issuedAt: isSet(object.issuedAt) ? globalThis.Number(object.issuedAt) : isSet(object.issued_at) ? globalThis.Number(object.issued_at) : 0,
      reportData: isSet(object.reportData) ? bytesFromBase64(object.reportData) : isSet(object.report_data) ? bytesFromBase64(object.report_data) : new Uint8Array(0),
      proof: isSet(object.proof) ? AttestationProof.fromJSON(object.proof) : void 0
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.providerType !== "") {
      obj.providerType = message.providerType;
    }
    if (message.workspaceId !== "") {
      obj.workspaceId = message.workspaceId;
    }
    if (message.measurement.length !== 0) {
      obj.measurement = base64FromBytes(message.measurement);
    }
    if (message.nonce.length !== 0) {
      obj.nonce = base64FromBytes(message.nonce);
    }
    if (message.issuedAt !== 0) {
      obj.issuedAt = Math.round(message.issuedAt);
    }
    if (message.reportData.length !== 0) {
      obj.reportData = base64FromBytes(message.reportData);
    }
    if (message.proof !== void 0) {
      obj.proof = AttestationProof.toJSON(message.proof);
    }
    return obj;
  },
  create(base) {
    return AttestationEvidence.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseAttestationEvidence();
    message.providerType = object.providerType ?? "";
    message.workspaceId = object.workspaceId ?? "";
    message.measurement = object.measurement ?? new Uint8Array(0);
    message.nonce = object.nonce ?? new Uint8Array(0);
    message.issuedAt = object.issuedAt ?? 0;
    message.reportData = object.reportData ?? new Uint8Array(0);
    message.proof = object.proof !== void 0 && object.proof !== null ? AttestationProof.fromPartial(object.proof) : void 0;
    return message;
  }
};
function createBaseAttestationProof() {
  return { signature: new Uint8Array(0), signerPubkey: new Uint8Array(0) };
}
var AttestationProof = {
  encode(message, writer = new BinaryWriter()) {
    if (message.signature.length !== 0) {
      writer.uint32(10).bytes(message.signature);
    }
    if (message.signerPubkey.length !== 0) {
      writer.uint32(18).bytes(message.signerPubkey);
    }
    return writer;
  },
  decode(input, length) {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === void 0 ? reader.len : reader.pos + length;
    const message = createBaseAttestationProof();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1: {
          if (tag !== 10) {
            break;
          }
          message.signature = reader.bytes();
          continue;
        }
        case 2: {
          if (tag !== 18) {
            break;
          }
          message.signerPubkey = reader.bytes();
          continue;
        }
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skip(tag & 7);
    }
    return message;
  },
  fromJSON(object) {
    return {
      signature: isSet(object.signature) ? bytesFromBase64(object.signature) : new Uint8Array(0),
      signerPubkey: isSet(object.signerPubkey) ? bytesFromBase64(object.signerPubkey) : isSet(object.signer_pubkey) ? bytesFromBase64(object.signer_pubkey) : new Uint8Array(0)
    };
  },
  toJSON(message) {
    const obj = {};
    if (message.signature.length !== 0) {
      obj.signature = base64FromBytes(message.signature);
    }
    if (message.signerPubkey.length !== 0) {
      obj.signerPubkey = base64FromBytes(message.signerPubkey);
    }
    return obj;
  },
  create(base) {
    return AttestationProof.fromPartial(base ?? {});
  },
  fromPartial(object) {
    const message = createBaseAttestationProof();
    message.signature = object.signature ?? new Uint8Array(0);
    message.signerPubkey = object.signerPubkey ?? new Uint8Array(0);
    return message;
  }
};
var RuntimeService = {
  /**
   * Liveness + version probe. Returns versions of both the API
   * daemon and the upstream supervisor it relays to.
   */
  ping: {
    path: "/ne.runtime.v1.Runtime/Ping",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(PingRequest.encode(value).finish()),
    requestDeserialize: (value) => PingRequest.decode(value),
    responseSerialize: (value) => Buffer.from(PingResponse.encode(value).finish()),
    responseDeserialize: (value) => PingResponse.decode(value)
  },
  /**
   * Launch one Firecracker microVM workspace. The supervisor stages
   * kernel + rootfs into a per-workspace jailer chroot, starts
   * Firecracker, configures it via its HTTP API socket, and boots.
   */
  createWorkspace: {
    path: "/ne.runtime.v1.Runtime/CreateWorkspace",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(CreateWorkspaceRequest.encode(value).finish()),
    requestDeserialize: (value) => CreateWorkspaceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(CreateWorkspaceResponse.encode(value).finish()),
    responseDeserialize: (value) => CreateWorkspaceResponse.decode(value)
  },
  /**
   * Tear down a registered workspace and reclaim host resources.
   * Maps onto SupervisorRequest::Terminate on the privileged side.
   */
  destroyWorkspace: {
    path: "/ne.runtime.v1.Runtime/DestroyWorkspace",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(DestroyWorkspaceRequest.encode(value).finish()),
    requestDeserialize: (value) => DestroyWorkspaceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(DestroyWorkspaceResponse.encode(value).finish()),
    responseDeserialize: (value) => DestroyWorkspaceResponse.decode(value)
  },
  /**
   * Run one command inside a workspace. The API daemon relays the
   * call through the supervisor, which opens a vsock connection to
   * the guest agent, asks it to spawn the command, and returns the
   * captured output. Phase 1 P0 is unary; server-streaming with
   * stdout/stderr chunks (PRD FR-4.5) lands in P1.
   */
  executeCommand: {
    path: "/ne.runtime.v1.Runtime/ExecuteCommand",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(ExecuteCommandRequest.encode(value).finish()),
    requestDeserialize: (value) => ExecuteCommandRequest.decode(value),
    responseSerialize: (value) => Buffer.from(ExecuteCommandResponse.encode(value).finish()),
    responseDeserialize: (value) => ExecuteCommandResponse.decode(value)
  },
  /**
   * Read entries from the supervisor's signed audit event log
   * (per-event Ed25519 + Merkle chain). Per FR-11.3 these events
   * are what the control plane eventually aggregates into its
   * tamper-evident store for compliance evidence packaging.
   */
  listEvents: {
    path: "/ne.runtime.v1.Runtime/ListEvents",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(ListEventsRequest.encode(value).finish()),
    requestDeserialize: (value) => ListEventsRequest.decode(value),
    responseSerialize: (value) => Buffer.from(ListEventsResponse.encode(value).finish()),
    responseDeserialize: (value) => ListEventsResponse.decode(value)
  },
  writeFile: {
    path: "/ne.runtime.v1.Runtime/WriteFile",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(WriteFileRequest.encode(value).finish()),
    requestDeserialize: (value) => WriteFileRequest.decode(value),
    responseSerialize: (value) => Buffer.from(WriteFileResponse.encode(value).finish()),
    responseDeserialize: (value) => WriteFileResponse.decode(value)
  },
  readFile: {
    path: "/ne.runtime.v1.Runtime/ReadFile",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(ReadFileRequest.encode(value).finish()),
    requestDeserialize: (value) => ReadFileRequest.decode(value),
    responseSerialize: (value) => Buffer.from(ReadFileResponse.encode(value).finish()),
    responseDeserialize: (value) => ReadFileResponse.decode(value)
  },
  /**
   * Pause a running workspace (freeze vCPUs in place).
   * DEFERRED (wedge-6.8): unsupported on current Firecracker (vsock dies on in-place resume); use snapshot/restore. Server returns Unsupported.
   */
  pauseWorkspace: {
    path: "/ne.runtime.v1.Runtime/PauseWorkspace",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(PauseWorkspaceRequest.encode(value).finish()),
    requestDeserialize: (value) => PauseWorkspaceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(PauseWorkspaceResponse.encode(value).finish()),
    responseDeserialize: (value) => PauseWorkspaceResponse.decode(value)
  },
  /**
   * Resume a previously paused workspace.
   * DEFERRED (wedge-6.8): unsupported on current Firecracker (vsock dies on in-place resume); use snapshot/restore. Server returns Unsupported.
   */
  resumeWorkspace: {
    path: "/ne.runtime.v1.Runtime/ResumeWorkspace",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(ResumeWorkspaceRequest.encode(value).finish()),
    requestDeserialize: (value) => ResumeWorkspaceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(ResumeWorkspaceResponse.encode(value).finish()),
    responseDeserialize: (value) => ResumeWorkspaceResponse.decode(value)
  },
  /** Snapshot a paused workspace into a reusable artifact. */
  snapshotWorkspace: {
    path: "/ne.runtime.v1.Runtime/SnapshotWorkspace",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(SnapshotWorkspaceRequest.encode(value).finish()),
    requestDeserialize: (value) => SnapshotWorkspaceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(SnapshotWorkspaceResponse.encode(value).finish()),
    responseDeserialize: (value) => SnapshotWorkspaceResponse.decode(value)
  },
  /** Restore a fresh workspace from an existing snapshot artifact. */
  restoreWorkspace: {
    path: "/ne.runtime.v1.Runtime/RestoreWorkspace",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(RestoreWorkspaceRequest.encode(value).finish()),
    requestDeserialize: (value) => RestoreWorkspaceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(RestoreWorkspaceResponse.encode(value).finish()),
    responseDeserialize: (value) => RestoreWorkspaceResponse.decode(value)
  },
  /**
   * Fork a fresh workspace from a snapshot artifact, resetting the new
   * guest's identity (hostname / machine-id / RNG) so it is distinct from
   * the source and any sibling fork.
   */
  forkWorkspace: {
    path: "/ne.runtime.v1.Runtime/ForkWorkspace",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(ForkWorkspaceRequest.encode(value).finish()),
    requestDeserialize: (value) => ForkWorkspaceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(ForkWorkspaceResponse.encode(value).finish()),
    responseDeserialize: (value) => ForkWorkspaceResponse.decode(value)
  },
  /**
   * Query warm-pool status for the configured tier (if any).
   * Returns immediately from the pool manager's in-memory state; safe
   * to call at high frequency for dashboard/health probes.
   */
  getPoolStatus: {
    path: "/ne.runtime.v1.Runtime/GetPoolStatus",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(GetPoolStatusRequest.encode(value).finish()),
    requestDeserialize: (value) => GetPoolStatusRequest.decode(value),
    responseSerialize: (value) => Buffer.from(GetPoolStatusResponse.encode(value).finish()),
    responseDeserialize: (value) => GetPoolStatusResponse.decode(value)
  },
  /**
   * Expose a guest port to host-based ingress routing, reachable at
   * {port}-{workspace_id}.{ingress_domain}. Optional per-port header
   * injection. The workspace must be networked.
   */
  exposePort: {
    path: "/ne.runtime.v1.Runtime/ExposePort",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(ExposePortRequest.encode(value).finish()),
    requestDeserialize: (value) => ExposePortRequest.decode(value),
    responseSerialize: (value) => Buffer.from(ExposePortResponse.encode(value).finish()),
    responseDeserialize: (value) => ExposePortResponse.decode(value)
  },
  /** Stop routing ingress to a previously exposed guest port. */
  unexposePort: {
    path: "/ne.runtime.v1.Runtime/UnexposePort",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(UnexposePortRequest.encode(value).finish()),
    requestDeserialize: (value) => UnexposePortRequest.decode(value),
    responseSerialize: (value) => Buffer.from(UnexposePortResponse.encode(value).finish()),
    responseDeserialize: (value) => UnexposePortResponse.decode(value)
  },
  /**
   * Generate attestation evidence for a workspace, binding a caller
   * nonce (challenge-response). The active provider determines the
   * proof type; the software fallback is Ed25519-signed.
   */
  getAttestationEvidence: {
    path: "/ne.runtime.v1.Runtime/GetAttestationEvidence",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value) => Buffer.from(GetAttestationEvidenceRequest.encode(value).finish()),
    requestDeserialize: (value) => GetAttestationEvidenceRequest.decode(value),
    responseSerialize: (value) => Buffer.from(GetAttestationEvidenceResponse.encode(value).finish()),
    responseDeserialize: (value) => GetAttestationEvidenceResponse.decode(value)
  }
};
var RuntimeClient = makeGenericClientConstructor(RuntimeService, "ne.runtime.v1.Runtime");
function bytesFromBase64(b64) {
  if (globalThis.Buffer) {
    return Uint8Array.from(globalThis.Buffer.from(b64, "base64"));
  } else {
    const bin = globalThis.atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; ++i) {
      arr[i] = bin.charCodeAt(i);
    }
    return arr;
  }
}
function base64FromBytes(arr) {
  if (globalThis.Buffer) {
    return globalThis.Buffer.from(arr).toString("base64");
  } else {
    const bin = [];
    arr.forEach((byte) => {
      bin.push(globalThis.String.fromCharCode(byte));
    });
    return globalThis.btoa(bin.join(""));
  }
}
function longToNumber(int64) {
  const num = globalThis.Number(int64.toString());
  if (num > globalThis.Number.MAX_SAFE_INTEGER) {
    throw new globalThis.Error("Value is larger than Number.MAX_SAFE_INTEGER");
  }
  if (num < globalThis.Number.MIN_SAFE_INTEGER) {
    throw new globalThis.Error("Value is smaller than Number.MIN_SAFE_INTEGER");
  }
  return num;
}
function isSet(value) {
  return value !== null && value !== void 0;
}

// src/client.ts
var CLIENT_CLOSED_MESSAGE = "Client has been closed";
function isServiceError(err) {
  return err instanceof Error && typeof err.code === "number" && typeof err.details === "string";
}
var Client2 = class {
  #stub;
  #defaultDeadlineMs;
  #closed = false;
  constructor(options) {
    if (typeof options?.target !== "string" || options.target.length === 0) {
      throw new TypeError("target must be a non-empty string");
    }
    const creds = options.credentials ?? credentials.createInsecure();
    this.#stub = new RuntimeClient(options.target, creds, options.channelOptions ?? {});
    this.#defaultDeadlineMs = options.deadlineMs;
  }
  /** Closes the underlying channel. Idempotent. */
  close() {
    if (this.#closed) return;
    this.#closed = true;
    this.#stub.close();
  }
  /** Symbol.dispose support — Node 22+ `using` semantics. */
  [Symbol.dispose]() {
    this.close();
  }
  /** Symbol.asyncDispose support — `await using` semantics. */
  async [Symbol.asyncDispose]() {
    this.close();
  }
  // ----- RPC methods ------------------------------------------------
  ping(options = {}) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.ping({}, this.#buildMetadata(), callOptions, callback)
    );
  }
  createWorkspace(options) {
    const network = options.enableNetwork ? {
      enableEgress: options.enableEgress ?? false,
      allowCidrs: options.allowCidrs ? [...options.allowCidrs] : [],
      allowHostnames: options.allowHostnames ? [...options.allowHostnames] : [],
      privacyRouter: options.enablePrivacyRouter ? {} : void 0,
      exposedPorts: options.exposedPorts ? options.exposedPorts.map((p) => ({
        port: p.port,
        injectHeaders: p.injectHeaders ? [...p.injectHeaders] : []
      })) : []
    } : void 0;
    const request = {
      workspaceId: options.workspaceId,
      kernelImagePath: options.kernelImagePath,
      rootfsImagePath: options.rootfsImagePath,
      rootfsReadOnly: options.rootfsReadOnly ?? true,
      vcpuCount: options.vcpuCount,
      memSizeMib: options.memSizeMib,
      guestVsockCid: options.guestVsockCid,
      kernelBootArgs: options.kernelBootArgs,
      tier: options.tier,
      network
    };
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.createWorkspace(request, this.#buildMetadata(), callOptions, callback)
    );
  }
  executeCommand(options) {
    const request = {
      workspaceId: options.workspaceId,
      command: options.command,
      args: options.args ? [...options.args] : [],
      timeoutMs: options.timeoutMs ?? 0,
      guestPort: options.guestPort ?? 0
    };
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.executeCommand(request, this.#buildMetadata(), callOptions, callback)
    );
  }
  writeFile(options) {
    const request = {
      workspaceId: options.workspaceId,
      path: options.path,
      content: options.content,
      guestPort: options.guestPort ?? 0
    };
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.writeFile(request, this.#buildMetadata(), callOptions, callback)
    );
  }
  readFile(options) {
    const request = {
      workspaceId: options.workspaceId,
      path: options.path,
      maxBytes: options.maxBytes ?? 0,
      guestPort: options.guestPort ?? 0
    };
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.readFile(request, this.#buildMetadata(), callOptions, callback)
    );
  }
  destroyWorkspace(options) {
    const request = {
      workspaceId: options.workspaceId,
      gracePeriodMs: options.gracePeriodMs ?? 2e3
    };
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.destroyWorkspace(request, this.#buildMetadata(), callOptions, callback)
    );
  }
  listEvents(options = {}) {
    const request = {
      workspaceId: options.workspaceId,
      sinceChainIndex: options.sinceChainIndex ?? 0,
      limit: options.limit ?? 0
    };
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.listEvents(request, this.#buildMetadata(), callOptions, callback)
    );
  }
  /** Pause a running workspace (freeze vCPUs in place).
   *
   *  The workspace must already exist and be in the running state.
   *  Use {@link resume} to unfreeze it afterwards.
   *
   *  Deferred: unsupported on current Firecracker; the server returns an Unsupported error. Use snapshot/restore instead. */
  pause(options) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.pauseWorkspace(
        { workspaceId: options.workspaceId },
        this.#buildMetadata(),
        callOptions,
        callback
      )
    );
  }
  /** Resume a previously paused workspace.
   *
   *  Deferred: unsupported on current Firecracker; the server returns an Unsupported error. Use snapshot/restore instead. */
  resume(options) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.resumeWorkspace(
        { workspaceId: options.workspaceId },
        this.#buildMetadata(),
        callOptions,
        callback
      )
    );
  }
  /** Snapshot a workspace into a reusable artifact.
   *
   *  Returns a {@link SnapshotWorkspaceResponse} whose `snapshotId`
   *  (ULID) can be passed to {@link restore} to boot a new workspace
   *  from this image.
   *
   *  When `live` is `false` (default) the workspace must be paused first.
   *  When `live` is `true` the source keeps running and stays reachable
   *  during the snapshot (the workspace must be running); the response
   *  `firecrackerPid` field carries the source's new Firecracker PID after
   *  the live hot-swap completes.  For non-live snapshots `firecrackerPid`
   *  is absent. */
  snapshot(options) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.snapshotWorkspace(
        { workspaceId: options.workspaceId, live: options.live ?? false },
        this.#buildMetadata(),
        callOptions,
        callback
      )
    );
  }
  /** Restore a fresh workspace from an existing snapshot artifact.
   *
   *  `snapshotId` is the ULID returned by a prior {@link snapshot}
   *  call. `newWorkspaceId` must satisfy the jailer's grammar
   *  `[a-zA-Z0-9-]{1,64}` and must not already exist. */
  restore(options) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.restoreWorkspace(
        { snapshotId: options.snapshotId, newWorkspaceId: options.newWorkspaceId },
        this.#buildMetadata(),
        callOptions,
        callback
      )
    );
  }
  /** Fork a fresh workspace from a snapshot, resetting its guest identity.
   *
   *  `snapshotId` is the ULID returned by a prior {@link snapshot} call.
   *  `newWorkspaceId` must satisfy the jailer grammar `[a-zA-Z0-9-]{1,64}`
   *  and must not already exist. The fork's hostname / machine-id / RNG are
   *  reset so it is distinct from the source; `hostname` defaults to
   *  `newWorkspaceId`. To fork N times, call this N times. */
  fork(options) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.forkWorkspace(
        {
          snapshotId: options.snapshotId,
          newWorkspaceId: options.newWorkspaceId,
          hostname: options.hostname ?? ""
        },
        this.#buildMetadata(),
        callOptions,
        callback
      )
    );
  }
  /** Query warm-pool status for the configured tier (if any).
   *
   *  Returns immediately from the pool manager's in-memory state; safe
   *  to call at high frequency for dashboard/health probes. */
  poolStatus(options = {}) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.getPoolStatus({}, this.#buildMetadata(), callOptions, callback)
    );
  }
  /** Expose a guest port to host-based ingress routing.
   *
   *  After a successful call the port is reachable at
   *  `{port}-{workspaceId}.{ingressDomain}`. The workspace must be
   *  running with networking enabled. */
  exposePort(options) {
    const request = {
      workspaceId: options.workspaceId,
      port: {
        port: options.port,
        injectHeaders: options.injectHeaders ? [...options.injectHeaders] : []
      }
    };
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.exposePort(request, this.#buildMetadata(), callOptions, callback)
    );
  }
  /** Stop routing ingress to a previously exposed guest port. */
  unexposePort(options) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.unexposePort(
        { workspaceId: options.workspaceId, port: options.port },
        this.#buildMetadata(),
        callOptions,
        callback
      )
    );
  }
  /** Generate attestation evidence for a running workspace.
   *
   *  `nonce` is the caller challenge (16..=64 bytes) bound into the
   *  returned evidence. The software-fallback provider signs with the
   *  runtime's Ed25519 identity key. */
  getAttestationEvidence(options) {
    return this.#unary(
      options.deadlineMs,
      (callOptions, callback) => this.#stub.getAttestationEvidence(
        { workspaceId: options.workspaceId, nonce: options.nonce },
        this.#buildMetadata(),
        callOptions,
        callback
      )
    );
  }
  // ----- internals --------------------------------------------------
  #buildMetadata() {
    return new Metadata();
  }
  #buildCallOptions(perCallMs) {
    const ms = perCallMs ?? this.#defaultDeadlineMs;
    if (ms === void 0) return {};
    return { deadline: new Date(Date.now() + ms) };
  }
  #unary(perCallDeadlineMs, invoke) {
    if (this.#closed) {
      return Promise.reject(new Error(CLIENT_CLOSED_MESSAGE));
    }
    return new Promise((resolve, reject) => {
      const callOptions = this.#buildCallOptions(perCallDeadlineMs);
      invoke(callOptions, (err, value) => {
        if (err !== null) {
          reject(err);
          return;
        }
        if (value === void 0) {
          const synthetic = Object.assign(
            new Error("grpc-js returned neither error nor value"),
            { code: status.INTERNAL, details: "empty response", metadata: new Metadata() }
          );
          reject(synthetic);
          return;
        }
        resolve(value);
      });
    });
  }
};

export { Client2 as Client, isServiceError };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map