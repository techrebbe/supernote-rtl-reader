import com.techrebbe.supernote.virtualspread.VirtualSpreadLinkAuthority;
import com.techrebbe.supernote.virtualspread.VirtualSpreadNavigation;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class VirtualSpreadLinkAuthorityTest {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        String internal = VirtualSpreadLinkAuthority.internal(
            1,
            "right",
            1,
            10.5,
            20.0,
            60.25,
            40.0,
            5,
            3,
            "right",
            "fit-source-page"
        );
        assertEquals(
            "internal canonical form",
            "v2|internal|1|right|1|4025000000000000|4034000000000000"
                + "|404e200000000000|4044000000000000|5|3|right"
                + "|fit-source-page",
            internal
        );

        String uri = VirtualSpreadLinkAuthority.uri(
            2,
            "left",
            1,
            0.0,
            -0.0,
            100.0,
            200.0,
            "https://example.com/שלום"
        );
        assertEquals(
            "URI canonical form",
            "v2|uri|2|left|1|0000000000000000|8000000000000000"
                + "|4059000000000000|4069000000000000"
                + "|68e5babec42067702f302e53b929c9f3e0041bd7164c7d90818ac5f281dd523b",
            uri
        );
        String layout = VirtualSpreadLinkAuthority.layout(
            "rtl", true, 7, 4, 864.0, 648.0, 0.0
        );
        assertEquals(
            "layout canonical form",
            "v1|layout|rtl|1|7|4|408b000000000000|"
                + "4084400000000000|0000000000000000",
            layout
        );
        String layoutDigest = VirtualSpreadLinkAuthority.layoutDigest(layout);
        assertEquals(
            "layout authority digest",
            "53d5b0b6c97118392220518325c8ee23f1a81d04bf430e01c893d88c490a4307",
            layoutDigest
        );
        assertEquals(
            "combined authority digest",
            "da3eeef9e81fe1f232cd3ac200c90841436855c9ac4a517b1a82021bc099800c",
            VirtualSpreadLinkAuthority.digest(new String[] {internal, uri})
        );
        assertEquals(
            "empty authority digest",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            VirtualSpreadLinkAuthority.digest(new String[0])
        );
        assertRejected(
            "URI authority rejects an unpaired high surrogate",
            new CheckedAction() {
                @Override
                public void run() throws Exception {
                    VirtualSpreadLinkAuthority.uri(
                        2, "left", 1, 0.0, 0.0, 1.0, 1.0, "\uD800"
                    );
                }
            }
        );
        assertRejected(
            "URI authority rejects an unpaired low surrogate",
            new CheckedAction() {
                @Override
                public void run() throws Exception {
                    VirtualSpreadLinkAuthority.uri(
                        2, "left", 1, 0.0, 0.0, 1.0, 1.0, "\uDC00"
                    );
                }
            }
        );
        assertRejected(
            "combined authority rejects malformed UTF-16 records",
            new CheckedAction() {
                @Override
                public void run() throws Exception {
                    VirtualSpreadLinkAuthority.digest(
                        new String[] {"valid", "\uD800"}
                    );
                }
            }
        );
        double[] sourceBox = {18.0, 36.0, 594.0, 756.0};
        double[] normalizedSourceBox = {36.0, 18.0, 756.0, 594.0};
        double[] rightSlot = {432.0, 0.0, 864.0, 648.0};
        double[] leftSlot = {0.0, 0.0, 432.0, 648.0};
        double[] rightDestination = {
            432.0, 151.20000000000002, 864.0, 496.79999999999995
        };
        double[] leftDestination = {
            0.0, 151.20000000000002, 432.0, 496.79999999999995
        };
        double[] rightTransform = {
            0.0, -0.6,
            0.6, 0.0,
            410.4, 507.6
        };
        double[] leftTransform = {
            0.0, -0.6,
            0.6, 0.0,
            -21.599999999999998, 507.6
        };
        String[] mappingRecords = {
            VirtualSpreadLinkAuthority.mapping(
                0, 0, "right", 90,
                sourceBox, normalizedSourceBox,
                rightSlot, rightDestination, 0.6, rightTransform
            ),
            VirtualSpreadLinkAuthority.mapping(
                1, 1, "right", 90,
                sourceBox, normalizedSourceBox,
                rightSlot, rightDestination, 0.6, rightTransform
            ),
            VirtualSpreadLinkAuthority.mapping(
                2, 1, "left", 90,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.6, leftTransform
            ),
        };
        String mappingDigest = VirtualSpreadLinkAuthority.mappingDigest(
            mappingRecords
        );
        assertEquals(
            "page-143 mapping digest",
            "646b905c12266774882e0c4d7ebbbca77b2f386f432979ebcbfcda1d9ace268a",
            mappingDigest
        );
        String signedZeroRecord = VirtualSpreadLinkAuthority.mapping(
            2, 1, "left", 90,
            sourceBox, normalizedSourceBox,
            new double[] {-0.0, 0.0, 432.0, 648.0},
            leftDestination, 0.6, leftTransform
        );
        assertEquals(
            "signed-zero mapping record",
            "page|2|1|left|90|4032000000000000|4042000000000000"
                + "|4082900000000000|4087a00000000000|4042000000000000"
                + "|4032000000000000|4087a00000000000|4082900000000000"
                + "|8000000000000000|0000000000000000|407b000000000000"
                + "|4084400000000000|0000000000000000|4062e66666666667"
                + "|407b000000000000|407f0ccccccccccc|3fe3333333333333"
                + "|0000000000000000|bfe3333333333333|3fe3333333333333"
                + "|0000000000000000|c035999999999999|407fb9999999999a",
            signedZeroRecord
        );
        assertEquals(
            "signed-zero mapping digest",
            "29e401f801b2c4867061385f9472dc061f3404db18427491af0dd64cca795832",
            VirtualSpreadLinkAuthority.mappingDigest(new String[] {
                mappingRecords[0], mappingRecords[1], signedZeroRecord
            })
        );
        String goldenSource =
            "0123456789abcdef0123456789abcdef"
            + "0123456789abcdef0123456789abcdef";
        String spreadViewId = VirtualSpreadLinkAuthority.viewId(
            goldenSource,
            "techrebbe.supernote.virtual-spread/v3",
            "techrebbe.supernote.virtual-spread-generator/v1",
            "rtl",
            true,
            864.0,
            648.0,
            0.0,
            mappingDigest
        );
        assertEquals(
            "page-143 view identity",
            "inkbridge-view-v1-"
                + "43f3e4f6cafaa07589e7ea1d27ae821d"
                + "785851a6f26ff0007f3faeb6323c6d74",
            spreadViewId
        );
        assertEquals(
            "signed-zero view identity",
            "inkbridge-view-v1-"
                + "426c932db050a81ef7d10c3491e24e9c"
                + "388b87bae25b371bfab67eacc5e2158d",
            VirtualSpreadLinkAuthority.viewId(
                goldenSource,
                "techrebbe.supernote.virtual-spread/v3",
                "techrebbe.supernote.virtual-spread-generator/v1",
                "rtl",
                true,
                864.0,
                648.0,
                -0.0,
                mappingDigest
            )
        );
        assertEquals(
            "page-143 deterministic output basename",
            "inkbridge-doc-v1-" + goldenSource + "." + spreadViewId
                + ".virtual-spread.pdf",
            VirtualSpreadLinkAuthority.outputBasename(
                goldenSource, spreadViewId
            )
        );
        assertEquals(
            "navigation view identity",
            "inkbridge-view-v1-"
                + "9c6d77c84ef97e7f73aa40156a78ef72"
                + "48b3ce1bca39d71eb2cda5341b040d2f",
            VirtualSpreadLinkAuthority.navigationViewId(
                goldenSource,
                "techrebbe.supernote.virtual-spread/v4",
                "techrebbe.supernote.virtual-spread-generator/v2",
                "rtl",
                true,
                864.0,
                648.0,
                0.0,
                mappingDigest,
                "7fbaa18d9b6c14ac6e1d5ea3062dccdb"
                    + "82c4092de9b56150676d19cc9695c172",
                true
            )
        );
        assertBoolean(
            "page-143 left mapping geometry",
            true,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 90,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.6, leftTransform,
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "wrong mapping side is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "right", 90,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.6, leftTransform,
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "wrong mapping rotation is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 180,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.6, leftTransform,
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "wrong mapping destination is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 90,
                sourceBox, normalizedSourceBox,
                leftSlot,
                new double[] {1.0, 151.2, 432.0, 496.8},
                0.6, leftTransform,
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "wrong mapping scale is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 90,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.5, leftTransform,
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "non-finite mapping transform is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 90,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.6,
                new double[] {0.0, -0.6, 0.6, 0.0, Double.NaN, 507.6},
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "reflected mapping transform is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 90,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.6,
                new double[] {0.0, 0.6, 0.6, 0.0, -21.6, 140.4},
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "nonzero quarter-turn residue is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 90,
                sourceBox, normalizedSourceBox,
                leftSlot, leftDestination, 0.6,
                new double[] {
                    1.0e-15, -0.6, 0.6, 0.0, -21.6, 507.6
                },
                864.0, 648.0, 0.0
            )
        );
        double tinyHalfWidth = (864.0 - 863.999) / 2.0;
        double tinyScale = tinyHalfWidth / 14400.0;
        double tinyBottom = (648.0 - tinyHalfWidth) / 2.0;
        assertBoolean(
            "tiny-scale reflected mapping is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 0,
                new double[] {0.0, 0.0, 14400.0, 14400.0},
                new double[] {0.0, 0.0, 14400.0, 14400.0},
                new double[] {0.0, 0.0, tinyHalfWidth, 648.0},
                new double[] {
                    0.0,
                    tinyBottom,
                    tinyHalfWidth,
                    tinyBottom + tinyHalfWidth
                },
                tinyScale,
                new double[] {
                    -tinyScale,
                    0.0,
                    0.0,
                    tinyScale,
                    tinyHalfWidth,
                    tinyBottom
                },
                864.0, 648.0, 863.999
            )
        );
        double farOffset = Math.scalb(1.0, 40);
        assertBoolean(
            "far-offset numerically unstable mapping is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 0,
                new double[] {
                    farOffset,
                    farOffset,
                    farOffset + 100.0,
                    farOffset + 200.0
                },
                new double[] {
                    farOffset,
                    farOffset,
                    farOffset + 100.0,
                    farOffset + 200.0
                },
                leftSlot,
                new double[] {54.0, 0.0, 378.0, 648.0},
                3.24,
                new double[] {
                    3.24,
                    0.0,
                    0.0,
                    3.24,
                    54.0 - 3.24 * farOffset,
                    -3.24 * farOffset
                },
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "overflowing mapping transform is rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 0,
                new double[] {1.0e308, 0.0, 1.1e308, 1.0},
                new double[] {1.0e308, 0.0, 1.1e308, 1.0},
                leftSlot, new double[] {0.0, 0.0, 432.0, 10.0}, 10.0,
                new double[] {10.0, 0.0, 0.0, 10.0, 0.0, 0.0},
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "non-generator scale and placement are rejected",
            false,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 0,
                new double[] {0.0, 0.0, 100.0, 100.0},
                new double[] {0.0, 0.0, 100.0, 100.0},
                leftSlot, new double[] {0.0, 0.0, 100.0, 100.0}, 1.0,
                new double[] {1.0, 0.0, 0.0, 1.0, 0.0, 0.0},
                864.0, 648.0, 0.0
            )
        );
        double[] simpleSource = new double[] {0.0, 0.0, 100.0, 200.0};
        assertBoolean(
            "generator rotation 0 transform is accepted",
            true,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 0, simpleSource, simpleSource, leftSlot,
                new double[] {54.0, 0.0, 378.0, 648.0}, 3.24,
                new double[] {3.24, 0.0, 0.0, 3.24, 54.0, 0.0},
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "generator rotation 90 transform is accepted",
            true,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 90, simpleSource,
                new double[] {0.0, 0.0, 200.0, 100.0}, leftSlot,
                new double[] {0.0, 216.0, 432.0, 432.0}, 2.16,
                new double[] {0.0, -2.16, 2.16, 0.0, 0.0, 432.0},
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "generator rotation 180 transform is accepted",
            true,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 180, simpleSource, simpleSource, leftSlot,
                new double[] {54.0, 0.0, 378.0, 648.0}, 3.24,
                new double[] {-3.24, 0.0, 0.0, -3.24, 378.0, 648.0},
                864.0, 648.0, 0.0
            )
        );
        assertBoolean(
            "generator rotation 270 transform is accepted",
            true,
            VirtualSpreadNavigation.mappingGeometryIsValid(
                "left", 270, simpleSource,
                new double[] {0.0, 0.0, 200.0, 100.0}, leftSlot,
                new double[] {0.0, 216.0, 432.0, 432.0}, 2.16,
                new double[] {0.0, 2.16, -2.16, 0.0, 432.0, 216.0},
                864.0, 648.0, 0.0
            )
        );
        Path fixture = Files.createTempFile("virtual-spread-authority", ".pdf");
        try {
            String sourceDigest =
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            String bound = "%PDF-1.7\n"
                + "%SNVirtualSpreadSourceSHA256:"
                + sourceDigest + "\n"
                + "%SNVirtualSpreadLayoutSHA256:"
                + layoutDigest + "\n"
                + "%SNVirtualSpreadLinksSHA256:"
                + "da3eeef9e81fe1f232cd3ac200c90841436855c9ac4a517b1a82021bc099800c"
                + "\n%SNVirtualSpreadMappingSHA256:"
                + mappingDigest
                + "\n%SNVirtualSpreadViewSHA256:"
                + spreadViewId.substring("inkbridge-view-v1-".length())
                + "\nstartxref\n42\n%%EOF\n";
            Files.write(fixture, bound.getBytes(StandardCharsets.ISO_8859_1));
            assertEquals(
                "PDF-bound source authority digest",
                sourceDigest,
                VirtualSpreadLinkAuthority.readPdfSourceDigest(
                    fixture.toFile()
                )
            );
            assertEquals(
                "PDF-bound authority digest",
                "da3eeef9e81fe1f232cd3ac200c90841436855c9ac4a517b1a82021bc099800c",
                VirtualSpreadLinkAuthority.readPdfDigest(fixture.toFile())
            );
            assertEquals(
                "PDF-bound layout authority digest",
                layoutDigest,
                VirtualSpreadLinkAuthority.readPdfLayoutDigest(fixture.toFile())
            );
            assertEquals(
                "PDF-bound mapping authority digest",
                mappingDigest,
                VirtualSpreadLinkAuthority.readPdfMappingDigest(
                    fixture.toFile()
                )
            );
            assertEquals(
                "PDF-bound view authority digest",
                spreadViewId.substring("inkbridge-view-v1-".length()),
                VirtualSpreadLinkAuthority.readPdfViewDigest(fixture.toFile())
            );
            String navigationDigest =
                "7fbaa18d9b6c14ac6e1d5ea3062dccdb"
                    + "82c4092de9b56150676d19cc9695c172";
            String navigationBound = bound.replace(
                "\nstartxref",
                "\n%SNVirtualSpreadNavigationSHA256:"
                    + navigationDigest + "\nstartxref"
            );
            Files.write(
                fixture,
                navigationBound.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "PDF-bound v4 view authority digest",
                spreadViewId.substring("inkbridge-view-v1-".length()),
                VirtualSpreadLinkAuthority.readPdfViewDigest(fixture.toFile())
            );
            assertEquals(
                "PDF-bound navigation authority digest",
                navigationDigest,
                VirtualSpreadLinkAuthority.readPdfNavigationDigest(
                    fixture.toFile()
                )
            );
            String payloadMarkers = "%PDF-1.7\n"
                + "%SNVirtualSpreadSourceSHA256:"
                + "11111111111111111111111111111111"
                + "11111111111111111111111111111111\n"
                + "%SNVirtualSpreadNavigationSHA256:"
                + "22222222222222222222222222222222"
                + "22222222222222222222222222222222\n"
                + "% copied source payload ends here\n"
                + navigationBound.substring("%PDF-1.7\n".length());
            Files.write(
                fixture,
                payloadMarkers.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "reserved source marker in copied payload is ignored",
                sourceDigest,
                VirtualSpreadLinkAuthority.readPdfSourceDigest(
                    fixture.toFile()
                )
            );
            assertEquals(
                "reserved navigation marker in copied payload is ignored",
                navigationDigest,
                VirtualSpreadLinkAuthority.readPdfNavigationDigest(
                    fixture.toFile()
                )
            );
            String duplicateNavigation = navigationBound.replace(
                "\nstartxref",
                "\n%SNVirtualSpreadNavigationSHA256:"
                    + "11111111111111111111111111111111"
                    + "11111111111111111111111111111111"
                    + "\nstartxref"
            );
            Files.write(
                fixture,
                duplicateNavigation.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "duplicate navigation authority markers are rejected",
                null,
                VirtualSpreadLinkAuthority.readPdfNavigationDigest(
                    fixture.toFile()
                )
            );
            String displacedNavigation = navigationBound.replace(
                "\nstartxref", "\n\nstartxref"
            );
            Files.write(
                fixture,
                displacedNavigation.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "displaced navigation authority marker is rejected",
                null,
                VirtualSpreadLinkAuthority.readPdfNavigationDigest(
                    fixture.toFile()
                )
            );
            String uppercaseMapping = bound.replace(
                mappingDigest,
                mappingDigest.toUpperCase()
            );
            Files.write(
                fixture,
                uppercaseMapping.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "uppercase mapping authority marker is rejected",
                null,
                VirtualSpreadLinkAuthority.readPdfMappingDigest(
                    fixture.toFile()
                )
            );
            String viewDigest = spreadViewId.substring(
                "inkbridge-view-v1-".length()
            );
            String uppercaseView = bound.replace(
                viewDigest,
                viewDigest.toUpperCase()
            );
            Files.write(
                fixture,
                uppercaseView.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "uppercase view authority marker is rejected",
                null,
                VirtualSpreadLinkAuthority.readPdfViewDigest(fixture.toFile())
            );
            String displacedSource = bound.replace(
                "\n%SNVirtualSpreadLayoutSHA256:",
                "\n\n%SNVirtualSpreadLayoutSHA256:"
            );
            Files.write(
                fixture,
                displacedSource.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "displaced source authority marker is rejected",
                null,
                VirtualSpreadLinkAuthority.readPdfSourceDigest(
                    fixture.toFile()
                )
            );
            String displacedLayout = bound.replace(
                "\n%SNVirtualSpreadLinksSHA256:",
                "\n\n%SNVirtualSpreadLinksSHA256:"
            );
            Files.write(
                fixture,
                displacedLayout.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "displaced layout authority marker is rejected",
                null,
                VirtualSpreadLinkAuthority.readPdfLayoutDigest(fixture.toFile())
            );
            String displaced = bound.replace("\nstartxref", "\n\nstartxref");
            Files.write(
                fixture,
                displaced.getBytes(StandardCharsets.ISO_8859_1)
            );
            assertEquals(
                "displaced authority marker is rejected",
                null,
                VirtualSpreadLinkAuthority.readPdfViewDigest(fixture.toFile())
            );
        } finally {
            Files.deleteIfExists(fixture);
        }
        System.out.println(
            "VirtualSpreadLinkAuthorityTest PASS assertions=" + assertions
        );
    }

    private static void assertEquals(
        String label,
        String expected,
        String actual
    ) {
        assertions++;
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(
                label + " expected=" + expected + " actual=" + actual
            );
        }
    }

    private static void assertRejected(
        String label,
        CheckedAction action
    ) throws Exception {
        assertions++;
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError(label + " expected rejection");
    }

    private static void assertBoolean(
        String label,
        boolean expected,
        boolean actual
    ) {
        assertions++;
        if (expected != actual) {
            throw new AssertionError(
                label + " expected=" + expected + " actual=" + actual
            );
        }
    }

    private interface CheckedAction {
        void run() throws Exception;
    }
}
