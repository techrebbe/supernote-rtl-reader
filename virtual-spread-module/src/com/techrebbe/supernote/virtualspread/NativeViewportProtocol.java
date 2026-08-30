package com.techrebbe.supernote.virtualspread;

import java.util.Set;

/** Version selection and representation binding for the viewport provider. */
public final class NativeViewportProtocol {
    public static final String SCHEMA_V3 =
        "techrebbe.supernote.virtual-spread/v3";
    public static final String GENERATOR_V1 =
        "techrebbe.supernote.virtual-spread-generator/v1";
    public static final String SCHEMA_V4 =
        "techrebbe.supernote.virtual-spread/v4";
    public static final String GENERATOR_V2 =
        "techrebbe.supernote.virtual-spread-generator/v2";

    private NativeViewportProtocol() {
    }

    /** Return the only provider protocol allowed for the verified manifest. */
    public static int versionForRepresentation(
        String schema,
        String generatorVersion,
        String navigationAuthoritySha256
    ) {
        if (SCHEMA_V3.equals(schema)
            && GENERATOR_V1.equals(generatorVersion)
            && navigationAuthoritySha256 == null) {
            return 1;
        }
        if (SCHEMA_V4.equals(schema)
            && GENERATOR_V2.equals(generatorVersion)
            && lowerSha256(navigationAuthoritySha256)) {
            return 2;
        }
        return -1;
    }

    /** Bind a v2 request to the exact schema-v4 representation evidence. */
    public static boolean v2EvidenceMatches(
        String recordSchema,
        String recordGeneratorVersion,
        String recordNavigationAuthority,
        String requestedSchema,
        String requestedGeneratorVersion,
        String requestedNavigationAuthority
    ) {
        return versionForRepresentation(
                recordSchema,
                recordGeneratorVersion,
                recordNavigationAuthority
            ) == 2
            && recordSchema.equals(requestedSchema)
            && recordGeneratorVersion.equals(requestedGeneratorVersion)
            && recordNavigationAuthority.equals(
                requestedNavigationAuthority
            );
    }

    /** Require the documented exact request-key set for each provider version. */
    public static boolean exactRequestFields(
        Set<String> fields,
        int protocolVersion
    ) {
        if (fields == null || (protocolVersion != 1 && protocolVersion != 2)) {
            return false;
        }
        int expectedCount = protocolVersion == 2 ? 12 : 9;
        if (fields.size() != expectedCount
            || !fields.contains("documentId")
            || !fields.contains("viewId")
            || !fields.contains("virtualPageIndex")
            || !fields.contains("nativeWidth")
            || !fields.contains("nativeHeight")
            || !fields.contains("documentPath")
            || !fields.contains("generatedPdfSha256")
            || !fields.contains("sidecarSha256")
            || !fields.contains("mappingAuthoritySha256")) {
            return false;
        }
        if (protocolVersion == 1) {
            return true;
        }
        return fields.contains("manifestSchema")
            && fields.contains("generatorVersion")
            && fields.contains("navigationAuthoritySha256");
    }

    private static boolean lowerSha256(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
