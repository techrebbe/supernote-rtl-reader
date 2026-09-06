'use strict';
// Executes the actual observation script against a closed fake Frida API.
// Any new native call, write, hook, or pixel-read method is absent and fails.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'pen_boundary_snapshot.js'), 'utf8');
const BASE = 0x10000000;
const INSTANCE = BASE + 0x167440;
const exportsMap = {
  _ZN16ThreadUpdateEpdc15set_path_bufferEPv: 0xc17b4,
  _ZN16ThreadUpdateEpdc16getDrawBufferMatEv: 0xbd29c,
  _ZN16ThreadUpdateEpdc14getFbBufferMatEv: 0xbb1f0,
  _ZZN16ThreadUpdateEpdc11getInstanceEvE8instance: 0x167440,
  _ZGVZN16ThreadUpdateEpdc11getInstanceEvE8instance: 0x167508,
  SCREEN_WIDTH: 0x142184, SCREEN_HEIGHT: 0x142188,
  g_docScreenSizeImageWidth: 0x169f4c, g_docScreenSizeImageHeight: 0x169f50
};
function run(options = {}) {
  const sent = [], accesses = [];
  let reads = 0;
  const memory = new Map([
    [BASE + 0xc17b4, 0xf9004c01], [BASE + 0xc17b8, 0xd65f03c0],
    [BASE + 0x167508, 1], [INSTANCE + 0x1c, 48],
    [INSTANCE + 0x78, 1404], [INSTANCE + 0x7a, 1872],
    [INSTANCE + 0xbc, 1404 * 1872], [INSTANCE + 0xc0, 0x786000],
    [INSTANCE + 0x98, 0x20000000], [INSTANCE + 0xa0, 0x20281ac0],
    [INSTANCE + 0xb0, 0x20503580],
    [BASE + 0x142184, 1404], [BASE + 0x142188, 1872],
    [BASE + 0x169f4c, 1404], [BASE + 0x169f50, 1872]
  ]);
  if (options.patch) options.patch(memory);
  class Pointer {
    constructor(address) { this.address = address; }
    add(offset) { return new Pointer(this.address + offset); }
    compare(other) { return Math.sign(this.address - other.address); }
    equals(other) { return this.address === other.address; }
    isNull() { return this.address === 0; }
    toString() { return '0x' + this.address.toString(16); }
    read() {
      accesses.push(this.address);
      assert(memory.has(this.address), 'unapproved memory/pixel read ' + this.toString());
      if (options.unstable && this.address === INSTANCE + 0x1c && ++reads === 2) return 49;
      return memory.get(this.address);
    }
    readPointer() { return new Pointer(this.read()); }
    readU32() { return this.read(); }
    readS32() { return this.read(); }
    readU16() { return this.read(); }
    readU8() { return this.read(); }
  }
  const module = {
    path: options.wrongPath ? '/wrong/librecgnition.so' : '/system_ext/app/drawPath/lib/arm64/librecgnition.so',
    base: new Pointer(BASE),
    findExportByName(name) {
      if (options.missing === name) return null;
      return new Pointer(BASE + exportsMap[name] + (options.badExport === name ? 4 : 0));
    }
  };
  const Process = {
    arch: options.arch || 'arm64', pointerSize: options.pointerSize || 8, id: 1425,
    getModuleByName(name) { assert.equal(name, 'librecgnition.so'); return module; },
    findRangeByAddress(pointer) {
      if (options.unreadable === pointer.address) return null;
      if (pointer.address >= BASE && pointer.address < BASE + 0x200000) {
        return {base: new Pointer(BASE), size: 0x200000, protection: 'r--'};
      }
      return {base: new Pointer(0x20000000), size: options.shortRange ? 1 : 0x786000,
        protection: options.nonReadable ? '---' : 'rw-', file: {path: '/dev/ebc'}};
    }
  };
  vm.runInNewContext(source, {Process, send: data => sent.push(data)}, {timeout: 1000});
  return {sent, accesses};
}
let checks = 0;
function passed(options) {
  const {sent} = run(options);
  assert.equal(sent.at(-1).success, true);
  assert.equal(sent[0].event, 'pen_boundary_metadata');
  assert.equal(sent[0].atomic, false);
  assert.equal(sent[0].data.draw.backingPath, '/dev/ebc');
  checks++;
}
function failed(options) {
  const {sent} = run(options);
  assert.equal(sent.at(-1).success, false);
  assert(!sent.some(event => event.event === 'pen_boundary_metadata'));
  checks++;
}
passed();
for (const name of Object.keys(exportsMap)) {
  failed({missing: name}); failed({badExport: name});
}
failed({arch: 'arm'}); failed({pointerSize: 4}); failed({wrongPath: true});
failed({unstable: true}); failed({nonReadable: true}); failed({shortRange: true});
failed({patch: m => m.set(BASE + 0xc17b4, 0)});
failed({patch: m => m.set(BASE + 0xc17b8, 0)});
failed({patch: m => m.set(BASE + 0x167508, 0)});
for (const offset of [0x98, 0xa0, 0xb0]) {
  failed({patch: m => m.set(INSTANCE + offset, 0)});
  failed({unreadable: INSTANCE + offset});
}
console.log('PASS ' + checks + ' bounded pen-buffer observation cases; no hardware claim.');
