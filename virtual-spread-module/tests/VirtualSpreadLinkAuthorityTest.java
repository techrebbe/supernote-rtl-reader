import com.techrebbe.supernote.virtualspread.VirtualSpreadLinkAuthority;

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
                VirtualSpreadLinkAuthority.readPdfDigest(fixture.toFile())
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
}
