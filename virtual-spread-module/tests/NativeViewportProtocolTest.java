import com.techrebbe.supernote.virtualspread.NativeViewportProtocol;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public final class NativeViewportProtocolTest {
    private static int assertions;

    private NativeViewportProtocolTest() {
    }

    public static void main(String[] args) {
        String digest =
            "0123456789abcdef0123456789abcdef"
                + "0123456789abcdef0123456789abcdef";
        assertEquals(
            "schema-v3 selects provider v1",
            1,
            NativeViewportProtocol.versionForRepresentation(
                NativeViewportProtocol.SCHEMA_V3,
                NativeViewportProtocol.GENERATOR_V1,
                null
            )
        );
        assertEquals(
            "schema-v4 selects provider v2",
            2,
            NativeViewportProtocol.versionForRepresentation(
                NativeViewportProtocol.SCHEMA_V4,
                NativeViewportProtocol.GENERATOR_V2,
                digest
            )
        );
        assertEquals(
            "v4 cannot use the v1 generator",
            -1,
            NativeViewportProtocol.versionForRepresentation(
                NativeViewportProtocol.SCHEMA_V4,
                NativeViewportProtocol.GENERATOR_V1,
                digest
            )
        );
        assertEquals(
            "v4 requires navigation authority",
            -1,
            NativeViewportProtocol.versionForRepresentation(
                NativeViewportProtocol.SCHEMA_V4,
                NativeViewportProtocol.GENERATOR_V2,
                null
            )
        );
        assertBoolean(
            "v2 request binds all representation fields",
            true,
            NativeViewportProtocol.v2EvidenceMatches(
                NativeViewportProtocol.SCHEMA_V4,
                NativeViewportProtocol.GENERATOR_V2,
                digest,
                NativeViewportProtocol.SCHEMA_V4,
                NativeViewportProtocol.GENERATOR_V2,
                digest
            )
        );
        assertBoolean(
            "stale v2 navigation authority is rejected",
            false,
            NativeViewportProtocol.v2EvidenceMatches(
                NativeViewportProtocol.SCHEMA_V4,
                NativeViewportProtocol.GENERATOR_V2,
                digest,
                NativeViewportProtocol.SCHEMA_V4,
                NativeViewportProtocol.GENERATOR_V2,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
        );
        Set<String> v1Fields = new HashSet<String>(Arrays.asList(
            "documentId", "viewId", "virtualPageIndex", "nativeWidth",
            "nativeHeight", "documentPath", "generatedPdfSha256",
            "sidecarSha256", "mappingAuthoritySha256"
        ));
        assertBoolean(
            "exact v1 request fields accepted",
            true,
            NativeViewportProtocol.exactRequestFields(v1Fields, 1)
        );
        Set<String> v2Fields = new HashSet<String>(v1Fields);
        v2Fields.add("manifestSchema");
        v2Fields.add("generatorVersion");
        v2Fields.add("navigationAuthoritySha256");
        assertBoolean(
            "exact v2 request fields accepted",
            true,
            NativeViewportProtocol.exactRequestFields(v2Fields, 2)
        );
        v2Fields.add("futureConstraint");
        assertBoolean(
            "unknown v2 request field rejected",
            false,
            NativeViewportProtocol.exactRequestFields(v2Fields, 2)
        );
        v2Fields.remove("futureConstraint");
        v2Fields.remove("navigationAuthoritySha256");
        assertBoolean(
            "missing v2 request field rejected",
            false,
            NativeViewportProtocol.exactRequestFields(v2Fields, 2)
        );
        System.out.println(
            "NativeViewportProtocolTest passed assertions=" + assertions
        );
    }

    private static void assertEquals(
        String label,
        int expected,
        int actual
    ) {
        assertions++;
        if (expected != actual) {
            throw new AssertionError(
                label + ": expected " + expected + ", got " + actual
            );
        }
    }

    private static void assertBoolean(
        String label,
        boolean expected,
        boolean actual
    ) {
        assertions++;
        if (expected != actual) {
            throw new AssertionError(
                label + ": expected " + expected + ", got " + actual
            );
        }
    }
}
