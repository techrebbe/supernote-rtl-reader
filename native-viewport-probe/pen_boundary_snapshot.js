'use strict';

// Bounded metadata observation on the separately hash-verified Nomad DrawPath
// binary. No hooks, native calls, pixel reads, pointer writes, or event replay.
// Use the exact-device/process runner; verify the file hash before AND after.
(function () {
  const expectedPath = '/system_ext/app/drawPath/lib/arm64/librecgnition.so';
  function requireThat(condition, message) {
    if (!condition) throw new Error(message);
  }
  function readable(address, bytes) {
    const range = Process.findRangeByAddress(address);
    requireThat(range !== null && range.protection.indexOf('r') >= 0 &&
      address.add(bytes).compare(range.base.add(range.size)) <= 0, 'unreadable metadata');
    return range;
  }
  function exportAt(module, name, offset) {
    const address = module.findExportByName(name);
    requireThat(address !== null && address.equals(module.base.add(offset)), 'ABI export mismatch: ' + name);
    return address;
  }
  function pointerMetadata(address) {
    readable(address, 8);
    const pointer = address.readPointer();
    requireThat(!pointer.isNull(), 'null buffer');
    const range = readable(pointer, 1);
    // Report mapping metadata only: do not read screen pixels or user ink.
    return {pointer: pointer.toString(), rangeBase: range.base.toString(),
      rangeSize: range.size, protection: range.protection,
      backingPath: range.file ? range.file.path : null};
  }
  try {
    requireThat(Process.arch === 'arm64' && Process.pointerSize === 8, 'wrong architecture');
    const module = Process.getModuleByName('librecgnition.so');
    requireThat(module.path === expectedPath, 'wrong module path');
    // Independent instruction evidence for the member offset: str x1,[x0,#0x98];ret.
    const setter = exportAt(module, '_ZN16ThreadUpdateEpdc15set_path_bufferEPv', 0xc17b4);
    readable(setter, 8);
    requireThat(setter.readU32() === 0xf9004c01 && setter.add(4).readU32() === 0xd65f03c0,
      'buffer offset instruction mismatch');
    exportAt(module, '_ZN16ThreadUpdateEpdc16getDrawBufferMatEv', 0xbd29c);
    exportAt(module, '_ZN16ThreadUpdateEpdc14getFbBufferMatEv', 0xbb1f0);
    const instance = exportAt(module, '_ZZN16ThreadUpdateEpdc11getInstanceEvE8instance', 0x167440);
    const guard = exportAt(module, '_ZGVZN16ThreadUpdateEpdc11getInstanceEvE8instance', 0x167508);
    readable(instance, 0xc8);
    readable(guard, 1);
    requireThat((guard.readU8() & 1) === 1, 'singleton not initialized');
    const globals = {
      SCREEN_WIDTH: 0x142184, SCREEN_HEIGHT: 0x142188,
      g_docScreenSizeImageWidth: 0x169f4c, g_docScreenSizeImageHeight: 0x169f50
    };
    function snapshot() {
      const values = {};
      Object.keys(globals).forEach(function (name) {
        const address = exportAt(module, name, globals[name]);
        readable(address, 4);
        values[name] = address.readS32();
      });
      return {fd: instance.add(0x1c).readS32(),
        deviceWidth: instance.add(0x78).readU16(), deviceHeight: instance.add(0x7a).readU16(),
        bytesPerPlane: instance.add(0xbc).readS32(), mappingBytes: instance.add(0xc0).readS32(),
        frame: pointerMetadata(instance.add(0x98)),
        draw: pointerMetadata(instance.add(0xa0)), alternateFrame: pointerMetadata(instance.add(0xb0)),
        globals: values};
    }
    const before = snapshot();
    const after = snapshot();
    requireThat(JSON.stringify(before) === JSON.stringify(after), 'metadata changed during observation');
    requireThat((guard.readU8() & 1) === 1, 'singleton ended during observation');
    send({event: 'pen_boundary_metadata', pid: Process.id, modulePath: module.path,
      requiredSha256: '3ce8bcf151e92899cb06c64e529723c560718aea36f070761c4ee9fe99bd57e2',
      atomic: false, observationOnly: true, data: before});
    send({event: 'service_snapshot_complete', success: true});
  } catch (error) {
    send({event: 'snapshot_error', error: String(error)});
    send({event: 'service_snapshot_complete', success: false});
  }
}());
