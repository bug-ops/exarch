/**
 * Shared tar and zip builders for the node tests. Lives outside the
 * `tests/*.test.js` glob and outside the package `files` list.
 */

const BLOCK = 512;

/** CRC-32 (IEEE) of `buffer`, as the unsigned 32-bit value stored in ZIP headers. */
function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** One ustar member: a header block with a valid checksum followed by `data` padded to a block. */
function tarEntry({ name, type = '0', data = Buffer.alloc(0), link = '' }) {
  const header = Buffer.alloc(BLOCK);
  header.write(name, 0);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  header.write('00000000000\0', 136);
  header.write(type, 156);
  header.write(link, 157);
  header.write('ustar\0', 257);
  header.write('00', 263);
  header.fill(0x20, 148, 156);
  const sum = header.reduce((acc, byte) => acc + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  const padded = Buffer.alloc(Math.ceil(data.length / BLOCK) * BLOCK);
  data.copy(padded);
  return Buffer.concat([header, padded]);
}

/** A tar archive of already built members (`tarEntry` results) plus the zero trailer. */
function tarArchive(members) {
  return Buffer.concat([...members, Buffer.alloc(2 * BLOCK)]);
}

/** A stored ZIP of `{ name, data, dir? }` entries; `dir` marks a directory, whose name ends in `/`. */
function zipArchive(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data = Buffer.alloc(0), dir = false } of entries) {
    const nameBytes = Buffer.from(dir && !name.endsWith('/') ? `${name}/` : name);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const localPart = Buffer.concat([local, nameBytes, data]);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(Buffer.concat([central, nameBytes]));
    locals.push(localPart);
    offset += localPart.length;
  }
  const centralPart = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralPart.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralPart, end]);
}

module.exports = { crc32, tarEntry, tarArchive, zipArchive };
