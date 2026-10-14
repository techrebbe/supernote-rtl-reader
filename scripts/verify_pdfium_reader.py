"""Fail closed on omitted/drifted PDFium classes, source, ABI payload or notices."""
import hashlib
import json
import struct
from build_pdfium_reader import JAVA,source_inputs


def sha(data):return hashlib.sha256(data).hexdigest()


def verify(native, root, classes):
    policy=root/'provenance/pdfium-reader.json'
    if not policy.is_file():return  # Generic non-PDFium package fixtures/old releases.
    declared=json.loads(policy.read_text(encoding='utf-8'))
    if declared.get('role')!='read-only-original-pdf' or declared.get('wrapper')!='librtlpdfiumreader.so' or \
        declared.get('v8') is not False or declared.get('xfa') is not False or declared.get('savesPdfOrAnnotations') is not False:
        raise ValueError('Unsupported production PDFium policy')
    lock=json.loads((root/'probes/pdfium-native/pdfium.lock.json').read_text(encoding='utf-8'))
    if declared.get('publisher')!=lock['publisher'] or declared.get('tag')!=lock['tag']:
        raise ValueError('Engine identity drift')
    for name in JAVA+('RenderBudget','Interaction'):
        if f'Lcom/supernotertlreader/{name};'.encode() not in classes:
            raise ValueError('Missing PDFium class '+name)
    receipt=json.loads(native.read('assets/pdfium/build-receipt.json'))
    expected={file.relative_to(root).as_posix():sha(file.read_bytes()) for file in source_inputs(root)}
    if receipt.get('schema')!=1 or receipt.get('engineTag')!=lock['tag'] or receipt.get('sourceHashes')!=expected:
        raise ValueError('PDFium source receipt mismatch')
    payload=receipt.get('payloadHashes')
    if not isinstance(payload,dict):raise ValueError('Missing complete PDFium payload receipt')
    actual={name for name in native.namelist() if name.startswith('assets/pdfium/') and
        name!='assets/pdfium/build-receipt.json'}
    for abi,vendor,bits,machine in [('armeabi-v7a','android-arm',1,40),('arm64-v8a','android-arm64',2,183)]:
        for name in ('libpdfium.so','librtlpdfiumreader.so'):
            path=f'lib/{abi}/{name}';actual.add(path)
            data=native.read(path)
            if len(data)<64 or data[:4]!=b'\x7fELF' or data[4]!=bits or data[5]!=1 or struct.unpack_from('<H',data,18)[0]!=machine:
                raise ValueError('PDFium native ABI mismatch')
            if name=='libpdfium.so' and sha(data)!=lock['extractedBinaries'][vendor+'/lib/libpdfium.so']:
                raise ValueError('Bundled engine is not the pinned binary')
    if set(payload)!=actual:raise ValueError('Incomplete/unexpected PDFium payload inventory')
    for name,value in payload.items():
        if sha(native.read(name))!=value:raise ValueError('PDFium payload hash mismatch: '+name)
    notices={name:sha(native.read(name)) for name in actual if name.startswith('assets/pdfium/')}
    fingerprint=sha(json.dumps(notices,sort_keys=True,separators=(',',':')).encode())
    if len(notices)!=declared.get('noticeCount') or fingerprint!=declared.get('noticeInventorySha256'):
        raise ValueError('Pinned complete license inventory missing or changed')
    if any('rtlpdfiumprobe' in name or name.endswith('.pdf') for name in native.namelist()):
        raise ValueError('Diagnostic/fixture leaked into production package')
