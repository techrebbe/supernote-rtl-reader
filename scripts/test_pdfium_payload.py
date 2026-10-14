"""Production payload omissions/tampering against real compiled JNI inputs."""
import io
import json
import os
from pathlib import Path
import unittest
import zipfile
from build_pdfium_reader import JAVA
from verify_pdfium_reader import verify

ROOT=Path(__file__).resolve().parent.parent


class Payload(unittest.TestCase):
    def setUp(self):
        stage=os.environ.get('RTL_PDFIUM_PAYLOAD_FIXTURE')
        if not stage:self.skipTest('Set real compiled payload fixture directory')
        main=Path(stage)/'android/app/src/main'
        self.items={file.relative_to(main).as_posix().replace('jniLibs/','lib/',1):file.read_bytes()
                    for folder in ('jniLibs','assets') for file in (main/folder).rglob('*') if file.is_file()}
        self.classes={f'Lcom/supernotertlreader/{name};'.encode() for name in JAVA+('RenderBudget','Interaction')}
    def check(self,items):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive:
            for name,data in items.items():archive.writestr(name,data)
        with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:verify(archive,ROOT,self.classes)
    def test_real_complete_payload(self):self.check(self.items)
    def test_missing_or_replaced_engine_and_wrapper_rejected(self):
        for name in ('lib/arm64-v8a/libpdfium.so','lib/armeabi-v7a/librtlpdfiumreader.so'):
            for remove in (True,False):
                changed=dict(self.items)
                if remove:del changed[name]
                else:changed[name]=b'wrong binary'
                with self.assertRaises((ValueError,KeyError)):self.check(changed)
    def test_rewritten_receipt_cannot_hide_omitted_notice(self):
        changed=dict(self.items);name='assets/pdfium/LICENSE';del changed[name]
        receipt=json.loads(changed['assets/pdfium/build-receipt.json'])
        del receipt['payloadHashes'][name]
        changed['assets/pdfium/build-receipt.json']=json.dumps(receipt).encode()
        with self.assertRaisesRegex(ValueError,'license inventory'):self.check(changed)
    def test_source_and_extra_fixture_drift_rejected(self):
        changed=dict(self.items);receipt=json.loads(changed['assets/pdfium/build-receipt.json'])
        receipt['sourceHashes']['native/pdfium_reader_core.cpp']='0'*64
        changed['assets/pdfium/build-receipt.json']=json.dumps(receipt).encode()
        with self.assertRaisesRegex(ValueError,'source receipt'):self.check(changed)
        changed=dict(self.items);changed['assets/fixture.pdf']=b'not permitted'
        with self.assertRaisesRegex(ValueError,'fixture'):self.check(changed)


if __name__=='__main__':unittest.main()
