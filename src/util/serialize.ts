const TYPE_LENGTH_MAP = {
  u8: 1,
  u16: 2,
  u32: 4,
  u64: 8
}

type UIntResolver = [type: 'u8' | 'u16' | 'u32', value: number];
type BigUIntResolver = [type: 'u64', value: bigint];
type VectorResolver = [type: 'v', value?: Uint8Array | Buffer | AnyResolver[]];
type AnyResolver = UIntResolver | BigUIntResolver | VectorResolver;
export type Resolvable = AnyResolver | Uint8Array | Buffer;

export function getVectorLength(r: VectorResolver) {
  return  r[1] ? Array.isArray(r[1]) ? r[1].reduce((p, r) => p + getResolverLength(r), 0) : r[1].length : 0;
}

export function getResolverLength(r: Resolvable): number {
  if (r instanceof Uint8Array || r instanceof Buffer) return r.length;
  if (r[0] === 'v') {
    const srcLength = getVectorLength(r);
    const lengthBytes = srcLength > 16383 ? 4 : srcLength > 63 ? 2 : 1;
    return lengthBytes + srcLength;
  }
  else return TYPE_LENGTH_MAP[r[0]];
}

export function serializeResolvers(resolvers: Resolvable[]) { 
  const length = resolvers.reduce((p, r) => p + getResolverLength(r), 0);
  const buffer = Buffer.alloc(length);

  let offset = 0;
  for (const resolver of resolvers) {
    if (resolver instanceof Uint8Array || resolver instanceof Buffer) {
      if (resolver instanceof Buffer) resolver.copy(buffer, offset);
      else buffer.set(resolver, offset);
      offset += resolver.length;
      continue;
    }
    switch (resolver[0]) {
      case 'u8': {
        buffer.writeUInt8(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'u16': {
        buffer.writeUInt16BE(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'u32': {
        buffer.writeUInt32BE(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'u64': {
        buffer.writeBigUInt64BE(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'v': {
        const srcLength = getVectorLength(resolver);
        const lengthBytes = srcLength > 16383 ? 4 : srcLength > 63 ? 2 : 1;
        switch (lengthBytes) {
            case 1:
              buffer.writeUInt8(srcLength, offset);
              break;
            case 2:
              buffer.writeUInt16BE(srcLength, offset);
              buffer[offset]! += 0x40;
              break;
            case 4:
              buffer.writeUInt32BE(srcLength, offset);
              buffer[offset]! += 0x80;
              break;
        }
        offset += lengthBytes;
        if (resolver[1]) {
          if (Array.isArray(resolver[1])) {
            const src = serializeResolvers(resolver[1]);
            src.copy(buffer, offset);
            offset += src.length;
          } else {
            if (resolver[1] instanceof Buffer) resolver[1].copy(buffer, offset);
            else buffer.set(resolver[1], offset);
            offset += resolver[1].length;
          }
        }
        break;
      }
    }
  }

  return buffer;
}