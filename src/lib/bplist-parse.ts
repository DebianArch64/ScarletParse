// Research from : https://opensource.apple.com/source/CF/CF-550/ForFoundationOnly.h
// BPLIST HEADER -> (first 8 bytes of file)
// typedef struct {
//   uint8_t	_magic[6];
//   uint8_t	_version[2];
// } CFBinaryPlistHeader;

// BPLIST TRAILER -> (last 32 bytes of file | contains offset of table which contains the actual data...)
// typedef struct {
//   uint8_t	_unused[5]; (6 NULL BYTES) | 0 - 5

//   uint8_t     _sortVersion; (this isn't included ???)

//   uint8_t	_offsetIntSize; | 6
//   uint8_t	_objectRefSize; | 7
//   uint64_t	_numObjects; | 8 - 16
//   uint64_t	_topObject; | 17 - 25
//   uint64_t	_offsetTableOffset; | 33
// } CFBinaryPlistTrailer;

// DataView.prototype.getUint64 = function (byteOffset: number, littleEndian: boolean): number {
//   // split 64-bit number into two 32-bit parts
//   const left = this.getUint32(byteOffset, littleEndian);
//   const right = this.getUint32(byteOffset + 4, littleEndian);

//   // combine the two 32-bit values
//   const combined = littleEndian
//     ? left + 2 ** 32 * right
//     : 2 ** 32 * left + right;

//   if (!Number.isSafeInteger(combined))
//     console.warn(combined, "exceeds MAX_SAFE_INTEGER. Precision may be lost");

//   return combined;
// };

import * as plist from "fast-plist";
function getUint64(
  buffer: ArrayBuffer,
  byteOffset: number,
  littleEndian: boolean
): number {
  const dataView = new DataView(buffer);
  // split 64-bit number into two 32-bit parts
  const left = dataView.getUint32(byteOffset, littleEndian);
  const right = dataView.getUint32(byteOffset + 4, littleEndian);

  // combine the two 32-bit values
  const combined = littleEndian
    ? left + 2 ** 32 * right
    : 2 ** 32 * left + right;

  if (!Number.isSafeInteger(combined))
    console.warn(combined, "exceeds MAX_SAFE_INTEGER. Precision may be lost");

  return combined;
}

function readUInt(buffer: ArrayBuffer, start: number = 0) {
  // start = start || 0;

  let l = 0;
  const dv = new DataView(buffer);
  for (let i = start; i < buffer.byteLength; i++) {
    l <<= 8;
    l |= /*buffer[i]*/ dv.getUint8(i) & 0xff;
  }
  return l;
}

const maxObjectSize = 32768;

function plistParse(buffer: ArrayBuffer): any {
  var enc = new TextDecoder("utf-8");
  if (enc.decode(buffer.slice(0, "bplist".length)) != "bplist") {
    return plist.parse(enc.decode(buffer));
  } else {
    return parse(buffer);
  }
}

function parse(buffer: ArrayBuffer): any {
  var enc = new TextDecoder("utf-8");
  if (enc.decode(buffer.slice(0, "bplist".length)) != "bplist") {
    return plist.parse(enc.decode(buffer));
  }

  const trailer = buffer.slice(buffer.byteLength - 32, buffer.byteLength);
  const numObjects = getUint64(trailer, 8, false);
  if (numObjects > maxObjectSize) {
    console.log("[BPLIST] Err: Max-Objects reached.");
    return;
  }

  const topObject = getUint64(trailer, 16, false);
  const offsetSize = new DataView(trailer).getUint8(6);
  const objectRefSize = new DataView(trailer).getUint8(7);
  const offsetTableOffset = getUint64(trailer, 24, false);
  console.log(numObjects + " objects !");
  console.log(offsetTableOffset + " table offset !");

  const offsetTable: number[] = [];
  for (let i = 0; i < numObjects; i++) {
    const offsetBytes = buffer.slice(
      offsetTableOffset + i * offsetSize,
      offsetTableOffset + (i + 1) * offsetSize
    );
    offsetTable[i] = readUInt(offsetBytes, 0);
  }

  const dv = new DataView(buffer);

  function parseObject(tableOffset: number): any {
    const offset = offsetTable[tableOffset];
    const type = dv.getUint8(offset);
    const objType = (type & 0xf0) >> 4;
    const objInfo = type & 0x0f;
    switch (objType) {
      case 0x0: // Boolean
        return parseSimple();
      case 0x1:
        return parseInteger();
      case 0x5: // ASCII
        return parsePlistString(false);
      case 0x6: // UTF-16
        return undefined; // TODO: fix utf-16 encoding !
      // return parsePlistString(true);
      case 0xa:
        return parseArray();
      case 0xd:
        return parseDictionary();
      default:
        break;
    }

    function parseSimple() {
      switch (objInfo) {
        case 0x0:
          return null;
        case 0x8:
          return false;
        case 0x9:
          return true;
        case 0xf:
          return null;
        default:
          return null;
      }
    }

    function parseInteger() {
      const length = Math.pow(2, objInfo);
      if (length < maxObjectSize) {
        const data = buffer.slice(offset + 1, offset + 1 + length);
        return new Uint8Array(data).reduce((acc, curr) => {
          acc <<= 8;
          acc |= curr & 255;
          return acc;
        });
      }
    }

    function parsePlistString(isUtf16): string {
      isUtf16 = isUtf16 || 0;
      let enc = "utf8";
      let length = objInfo;
      let stroffset = 1;
      if (objInfo == 0xf) {
        const int_type = dv.getUint8(offset + 1);
        const intType = (int_type & 0xf0) / 0x10;
        if (intType != 0x1) {
          console.error("UNEXPECTED LENGTH-INT TYPE! " + intType);
        }
        const intInfo = int_type & 0x0f;
        const intLength = Math.pow(2, intInfo);
        stroffset = 2 + intLength;
        if (intLength < 3) {
          length = readUInt(buffer.slice(offset + 2, offset + 2 + intLength));
        } else {
          length = readUInt(buffer.slice(offset + 2, offset + 2 + intLength));
        }
      }
      // length is String length -> to get byte length multiply by 2, as 1 character takes 2 bytes in UTF-16
      length *= isUtf16 + 1;
      if (length < maxObjectSize) {
        let plistString = buffer.slice(
          offset + stroffset,
          offset + stroffset + length
        );
        if (isUtf16) {
          plistString = swapBytes(plistString);
          enc = "ucs2";
        }

        var decoder = new TextDecoder(enc);
        return decoder.decode(plistString);
      }
    }

    function parseArray() {
      let length = objInfo;
      let arrayoffset = 1;
      if (objInfo == 0xf) {
        const int_type = buffer[offset + 1];
        const intType = (int_type & 0xf0) / 0x10;
        if (intType != 0x1) {
          console.error("0xa: UNEXPECTED LENGTH-INT TYPE! " + intType);
        }
        const intInfo = int_type & 0x0f;
        const intLength = Math.pow(2, intInfo);
        arrayoffset = 2 + intLength;
        if (intLength < 3) {
          length = readUInt(buffer.slice(offset + 2, offset + 2 + intLength));
        } else {
          length = readUInt(buffer.slice(offset + 2, offset + 2 + intLength));
        }
      }
      if (length * objectRefSize > maxObjectSize) {
        console.error("Too little heap space available!");
      }
      const array = [];
      for (let i = 0; i < length; i++) {
        const objRef = readUInt(
          buffer.slice(
            offset + arrayoffset + i * objectRefSize,
            offset + arrayoffset + (i + 1) * objectRefSize
          )
        );
        array[i] = parseObject(objRef);
      }
      return array;
    }

    function parseDictionary() {
      let length = objInfo;
      let dictoffset = 1;
      if (objInfo == 0xf) {
        const int_type = dv.getUint8(offset + 1);
        const intType = (int_type & 0xf0) / 0x10;
        if (intType != 0x1) {
          console.error("0xD: UNEXPECTED LENGTH-INT TYPE! " + intType);
        }
        const intInfo = int_type & 0x0f;
        const intLength = Math.pow(2, intInfo);
        dictoffset = 2 + intLength;
        if (intLength < 3) {
          length = readUInt(buffer.slice(offset + 2, offset + 2 + intLength));
        } else {
          length = readUInt(buffer.slice(offset + 2, offset + 2 + intLength));
        }
      }
      if (length * 2 * objectRefSize > maxObjectSize) {
        throw new Error("Too little heap space available!");
      }

      const dict = {};
      for (let i = 0; i < length; i++) {
        const keyRef = readUInt(
          buffer.slice(
            offset + dictoffset + i * objectRefSize,
            offset + dictoffset + (i + 1) * objectRefSize
          )
        );
        const valRef = readUInt(
          buffer.slice(
            offset + dictoffset + length * objectRefSize + i * objectRefSize,
            offset +
              dictoffset +
              length * objectRefSize +
              (i + 1) * objectRefSize
          )
        );
        const key = parseObject(keyRef);
        const val = parseObject(valRef);

        dict[key] = val;
      }
      return dict;
    }
  }
  return parseObject(topObject);
}

function swapBytes(buffer: ArrayBuffer) {
  const len = buffer.byteLength;
  const dv = new DataView(buffer);
  for (let i = 0; i < len; i += 2) {
    const a = dv.getUint8(i);
    dv.setUint8(i, dv.getUint8(i + 1));
    dv.setUint8(i + 1, a);
  }
  return buffer;
}

export { plistParse };
