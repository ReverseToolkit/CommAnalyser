export class Buffer extends Uint8Array {
  static from (value, encoding) {
    if (value instanceof ArrayBuffer) {
      return new Buffer(new Uint8Array(value));
    }
    if (ArrayBuffer.isView(value)) {
      return new Buffer(value);
    }
    if (Array.isArray(value)) {
      return new Buffer(Uint8Array.from(value));
    }
    if (typeof value === 'string') {
      const bytes = encoding === 'utf8' || encoding === undefined
        ? new TextEncoder().encode(value)
        : new TextEncoder().encode(value);
      return new Buffer(bytes);
    }
    return new Buffer(0);
  }

  static alloc (size) {
    return new Buffer(size);
  }

  static concat (list) {
    const total = list.reduce((n, item) => n + item.length, 0);
    const out = new Buffer(total);
    let offset = 0;
    for (const item of list) {
      out.set(item, offset);
      offset += item.length;
    }
    return out;
  }

  writeUInt32LE (value, offset) {
    new DataView(this.buffer, this.byteOffset, this.byteLength).setUint32(offset, value, true);
    return offset + 4;
  }

  writeUInt16LE (value, offset) {
    new DataView(this.buffer, this.byteOffset, this.byteLength).setUint16(offset, value, true);
    return offset + 2;
  }

  copy (target, targetStart = 0) {
    target.set(this, targetStart);
    return this.length;
  }
}

export default Buffer;
