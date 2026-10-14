"""Focused tests against actual pinned PDFium, not a copied parser model."""
import argparse
import hashlib
import unittest
from pathlib import Path
from host_probe import Fixture, FIXTURE_SHA

parser=argparse.ArgumentParser()
parser.add_argument('--engine',required=True,type=Path)
parser.add_argument('--fixture',required=True,type=Path)
args=parser.parse_args()


class ActualPdfium(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine=Fixture(args.engine,args.fixture)
        cls.models=[]
        for i in range(4):
            with cls.engine.page(i) as page:
                cls.models.append(cls.engine.inspect_page(page))

    @classmethod
    def tearDownClass(cls):
        cls.engine.close()
        cls.engine.close()
        with cls().assertRaises(RuntimeError):
            with cls.engine.page(0):
                pass
        if hashlib.sha256(args.fixture.read_bytes()).hexdigest()!=FIXTURE_SHA:
            raise AssertionError('Fixture mutated')

    def test_exact_direct_named_and_same_page_original_targets(self):
        links=self.models[0]['links']
        self.assertEqual(len(links),5)
        self.assertEqual(links[0]['action'],{'kind':'internal','pageIndex':1,'mode':'Fit'})
        self.assertEqual(links[1]['action'],{'kind':'internal','pageIndex':2,'mode':'XYZ','left':44.0,'top':738.0,'zoom':1.25})
        self.assertEqual(links[2]['action'],{'kind':'internal','pageIndex':0,'mode':'XYZ','left':44.0,'top':240.0,'zoom':None})
        self.assertEqual(self.engine.destination(self.engine.lib.FPDF_GetNamedDestByName(self.engine.doc,b'chapter-three')),links[1]['action'])

    def test_external_observed_never_opened_and_script_disabled(self):
        links=self.models[0]['links']
        self.assertEqual(links[3]['action'],{'kind':'external-confirmation-required','uri':'https://example.org/rtl-test'})
        self.assertEqual(links[4]['action']['kind'],'unsupported')

    def test_outline_order_hierarchy_unicode_and_exact_pages(self):
        tree=self.engine.outlines()
        self.assertEqual([n['title'] for n in tree],['Part one','Appendix'])
        self.assertEqual([n['title'] for n in tree[0]['children']],['Chapter three','ברכה'])
        self.assertEqual([n['destination']['pageIndex'] for n in tree[0]['children']],[2,3])
        self.assertEqual(tree[1]['destination']['pageIndex'],3)

    def test_crop_rotation_and_exact_renderer_mapping(self):
        self.assertEqual(self.models[1]['size'],[720.0,570.0])
        self.assertEqual(self.models[1]['crop'],[20.0,30.0,590.0,750.0])
        with self.engine.page(1) as page:
            pixels,source=self.engine.geometry(page,1440,1140,[40,50])
            self.assertEqual(pixels,[40,40])
            self.assertAlmostEqual(source[0],40,places=5)
            self.assertAlmostEqual(source[1],50,places=5)

    def test_embedded_english_text_and_actual_glyph_hit(self):
        for model in self.models:
            self.assertIn('Selectable phrase: original PDF text, not a page image.',model['text'])
            self.assertGreater(model['charBoxes'],0)
            self.assertGreaterEqual(model['textHitIndex'],0)

    def test_invalid_page_and_pixel_budget_refuse_before_allocation(self):
        for invalid in [-1,4,True,1.5]:
            with self.assertRaises(RuntimeError):
                with self.engine.page(invalid):
                    pass
        with self.engine.page(0) as page:
            with self.assertRaises(RuntimeError):
                self.engine.render(page,4001,4001,'unused.png')
        self.assertFalse(Path('unused.png').exists())

    def test_fixture_identity_unchanged(self):
        self.assertEqual(hashlib.sha256(args.fixture.read_bytes()).hexdigest(),FIXTURE_SHA)


unittest.main(argv=['test_probe.py'],verbosity=2)
