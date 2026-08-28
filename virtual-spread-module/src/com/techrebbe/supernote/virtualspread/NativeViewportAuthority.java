package com.techrebbe.supernote.virtualspread;

/**
 * Pure, host-testable authority for the native Virtual Spread page canvas.
 *
 * <p>The input matrix is Supernote/MuPDF's live PDF-to-origin-bitmap matrix.
 * Virtual Spread coordinates use the PDF bottom-left convention, while MuPDF
 * and native stroke samples use a top-left convention. The resulting affine
 * therefore includes the authoritative Y inversion, render translation,
 * fitting insets, and any linear rotation/skew reported by the native reader.
 */
public final class NativeViewportAuthority {
    static final int SCHEMA_VERSION = 1;
    static final String AUTHORITY = "rtl-reader-native-viewport-v1";
    static final String DOCUMENT_ID_PREFIX = "inkbridge-doc-v1-";
    static final String VIEW_ID_PREFIX = "inkbridge-view-v1-";
    static final double SINGULARITY_EPSILON = 1.0e-12;
    static final double NATIVE_EDGE_SNAP_PIXELS = 0.25d;
    static final double NATIVE_BOUNDS_RELATIVE_EPSILON = 1.0e-9d;

    private NativeViewportAuthority() {
    }

    public static final class Descriptor {
        public final String documentId;
        public final String viewId;
        public final int virtualPageIndex;
        public final int nativeWidth;
        public final int nativeHeight;
        public final double[] spreadToNative;

        private Descriptor(
            String documentId,
            String viewId,
            int virtualPageIndex,
            int nativeWidth,
            int nativeHeight,
            double[] spreadToNative
        ) {
            this.documentId = documentId;
            this.viewId = viewId;
            this.virtualPageIndex = virtualPageIndex;
            this.nativeWidth = nativeWidth;
            this.nativeHeight = nativeHeight;
            this.spreadToNative = spreadToNative.clone();
        }

        public static Descriptor validated(
            String documentId,
            String viewId,
            int virtualPageIndex,
            int nativeWidth,
            int nativeHeight,
            double[] spreadToNative
        ) {
            requireIdentity(documentId, DOCUMENT_ID_PREFIX, "documentId");
            requireIdentity(viewId, VIEW_ID_PREFIX, "viewId");
            if (virtualPageIndex < 0) {
                throw new IllegalArgumentException(
                    "virtualPageIndex must be zero-based and non-negative"
                );
            }
            if (nativeWidth <= 1 || nativeHeight <= 1) {
                throw new IllegalArgumentException(
                    "nativePageSize must contain positive pixel dimensions"
                );
            }
            if (spreadToNative == null || spreadToNative.length != 6) {
                throw new IllegalArgumentException(
                    "spreadToNative must contain six coefficients"
                );
            }
            double[] coefficients = spreadToNative.clone();
            for (int index = 0; index < coefficients.length; index++) {
                coefficients[index] = finite(
                    positiveZero(coefficients[index]),
                    "spreadToNative[" + index + "]"
                );
            }
            requireStable(coefficients);
            return new Descriptor(
                documentId,
                viewId,
                virtualPageIndex,
                nativeWidth,
                nativeHeight,
                coefficients
            );
        }

        public String canonicalJson() {
            StringBuilder json = new StringBuilder(512);
            json.append('{');
            json.append("\"schemaVersion\":1,");
            json.append("\"authority\":\"").append(AUTHORITY).append("\",");
            json.append("\"documentId\":\"").append(documentId).append("\",");
            json.append("\"viewId\":\"").append(viewId).append("\",");
            json.append("\"virtualPageIndex\":").append(virtualPageIndex)
                .append(',');
            json.append("\"nativePageSize\":[")
                .append(nativeWidth).append(',').append(nativeHeight)
                .append("],");
            json.append("\"spreadToNative\":[");
            for (int index = 0; index < spreadToNative.length; index++) {
                if (index > 0) {
                    json.append(',');
                }
                json.append(Double.toString(spreadToNative[index]));
            }
            json.append("]}");
            return json.toString();
        }
    }

    public static Descriptor fromNativeRender(
        String documentId,
        String viewId,
        int virtualPageIndex,
        double spreadWidth,
        double spreadHeight,
        int nativeWidth,
        int nativeHeight,
        int originBitmapWidth,
        int originBitmapHeight,
        double[] pdfToOriginBitmap,
        double offsetX,
        double offsetY
    ) {
        requirePositiveFinite(spreadWidth, "spreadWidth");
        requirePositiveFinite(spreadHeight, "spreadHeight");
        if (nativeWidth <= 1 || nativeHeight <= 1
            || originBitmapWidth <= 1 || originBitmapHeight <= 1) {
            throw new IllegalArgumentException(
                "native and origin bitmap dimensions must exceed one pixel"
            );
        }
        if (pdfToOriginBitmap == null || pdfToOriginBitmap.length != 6) {
            throw new IllegalArgumentException(
                "pdfToOriginBitmap must contain six coefficients"
            );
        }
        double[] matrix = pdfToOriginBitmap.clone();
        for (int index = 0; index < matrix.length; index++) {
            matrix[index] = finite(
                matrix[index],
                "pdfToOriginBitmap[" + index + "]"
            );
        }
        finite(offsetX, "offsetX");
        finite(offsetY, "offsetY");

        // MuPDF consumes top-left page coordinates. Compose the PDF
        // bottom-left -> top-left flip before its native render matrix.
        double originA = matrix[0];
        double originB = matrix[1];
        double originC = -matrix[2];
        double originD = -matrix[3];
        double originE = matrix[2] * spreadHeight + matrix[4] + offsetX;
        double originF = matrix[3] * spreadHeight + matrix[5] + offsetY;

        // Bitmap extents are continuous [0,width]/[0,height], whereas the
        // element API normalizes native stroke samples over pixel centers
        // [0,width-1]/[0,height-1]. This conversion is what makes the
        // descriptor agree exactly with PluginFileAPI.getPageSize.
        double pixelScaleX = (nativeWidth - 1.0d) / originBitmapWidth;
        double pixelScaleY = (nativeHeight - 1.0d) / originBitmapHeight;
        double[] transform = new double[] {
            originA * pixelScaleX,
            originB * pixelScaleY,
            originC * pixelScaleX,
            originD * pixelScaleY,
            originE * pixelScaleX,
            originF * pixelScaleY
        };
        transform = snapRenderBounds(
            transform,
            spreadWidth,
            spreadHeight,
            nativeWidth,
            nativeHeight
        );
        requireSpreadInsideNative(
            transform,
            spreadWidth,
            spreadHeight,
            nativeWidth,
            nativeHeight
        );
        return Descriptor.validated(
            documentId,
            viewId,
            virtualPageIndex,
            nativeWidth,
            nativeHeight,
            transform
        );
    }

    private static double[] snapRenderBounds(
        double[] transform,
        double spreadWidth,
        double spreadHeight,
        int nativeWidth,
        int nativeHeight
    ) {
        double[][] corners = corners(
            transform,
            spreadWidth,
            spreadHeight
        );
        double minX = Double.POSITIVE_INFINITY;
        double maxX = Double.NEGATIVE_INFINITY;
        double minY = Double.POSITIVE_INFINITY;
        double maxY = Double.NEGATIVE_INFINITY;
        for (double[] corner : corners) {
            minX = Math.min(minX, corner[0]);
            maxX = Math.max(maxX, corner[0]);
            minY = Math.min(minY, corner[1]);
            maxY = Math.max(maxY, corner[1]);
        }
        double nativeMaxX = nativeWidth - 1.0d;
        double nativeMaxY = nativeHeight - 1.0d;
        if (minX < -NATIVE_EDGE_SNAP_PIXELS
            || maxX > nativeMaxX + NATIVE_EDGE_SNAP_PIXELS
            || minY < -NATIVE_EDGE_SNAP_PIXELS
            || maxY > nativeMaxY + NATIVE_EDGE_SNAP_PIXELS) {
            throw new IllegalArgumentException(
                "native render lies outside the reported page canvas"
            );
        }
        double desiredMinX = near(minX, 0.0d) ? 0.0d : minX;
        double desiredMaxX = near(maxX, nativeMaxX) ? nativeMaxX : maxX;
        double desiredMinY = near(minY, 0.0d) ? 0.0d : minY;
        double desiredMaxY = near(maxY, nativeMaxY) ? nativeMaxY : maxY;
        double width = maxX - minX;
        double height = maxY - minY;
        if (!(width > 0.0d) || !(height > 0.0d)) {
            throw new IllegalArgumentException("native render bounds are empty");
        }
        double postScaleX = (desiredMaxX - desiredMinX) / width;
        double postScaleY = (desiredMaxY - desiredMinY) / height;
        double postTranslateX = desiredMinX - postScaleX * minX;
        double postTranslateY = desiredMinY - postScaleY * minY;
        return new double[] {
            positiveZero(transform[0] * postScaleX),
            positiveZero(transform[1] * postScaleY),
            positiveZero(transform[2] * postScaleX),
            positiveZero(transform[3] * postScaleY),
            positiveZero(transform[4] * postScaleX + postTranslateX),
            positiveZero(transform[5] * postScaleY + postTranslateY)
        };
    }

    public static void requireSpreadInsideNative(
        double[] transform,
        double spreadWidth,
        double spreadHeight,
        int nativeWidth,
        int nativeHeight
    ) {
        requirePositiveFinite(spreadWidth, "spreadWidth");
        requirePositiveFinite(spreadHeight, "spreadHeight");
        if (nativeWidth <= 1 || nativeHeight <= 1) {
            throw new IllegalArgumentException("native page is empty");
        }
        double maxX = nativeWidth - 1.0d;
        double maxY = nativeHeight - 1.0d;
        for (double[] corner : corners(transform, spreadWidth, spreadHeight)) {
            double toleranceX = NATIVE_BOUNDS_RELATIVE_EPSILON
                * Math.max(1.0d, Math.max(Math.abs(corner[0]), maxX));
            double toleranceY = NATIVE_BOUNDS_RELATIVE_EPSILON
                * Math.max(1.0d, Math.max(Math.abs(corner[1]), maxY));
            if (!Double.isFinite(corner[0]) || !Double.isFinite(corner[1])
                || corner[0] < -toleranceX
                || corner[0] > maxX + toleranceX
                || corner[1] < -toleranceY
                || corner[1] > maxY + toleranceY) {
                throw new IllegalArgumentException(
                    "spreadToNative places the spread outside the native canvas"
                );
            }
        }
    }

    private static double[][] corners(
        double[] transform,
        double width,
        double height
    ) {
        requireStable(transform);
        return new double[][] {
            apply(transform, 0.0d, 0.0d),
            apply(transform, width, 0.0d),
            apply(transform, 0.0d, height),
            apply(transform, width, height)
        };
    }

    private static double[] apply(double[] transform, double x, double y) {
        return new double[] {
            transform[0] * x + transform[2] * y + transform[4],
            transform[1] * x + transform[3] * y + transform[5]
        };
    }

    private static void requireStable(double[] transform) {
        if (transform == null || transform.length != 6) {
            throw new IllegalArgumentException("affine transform is unavailable");
        }
        for (int index = 0; index < transform.length; index++) {
            finite(transform[index], "affine[" + index + "]");
        }
        double scale = Math.max(
            Math.max(Math.abs(transform[0]), Math.abs(transform[1])),
            Math.max(Math.abs(transform[2]), Math.abs(transform[3]))
        );
        if (!(scale > 0.0d)) {
            throw new IllegalArgumentException("affine transform is singular");
        }
        double a = transform[0] / scale;
        double b = transform[1] / scale;
        double c = transform[2] / scale;
        double d = transform[3] / scale;
        double determinant = a * d - b * c;
        if (!Double.isFinite(determinant)
            || Math.abs(determinant) <= SINGULARITY_EPSILON) {
            throw new IllegalArgumentException(
                "affine transform is numerically unstable"
            );
        }
    }

    private static boolean near(double value, double boundary) {
        return Math.abs(value - boundary) <= NATIVE_EDGE_SNAP_PIXELS;
    }

    private static void requireIdentity(
        String value,
        String prefix,
        String label
    ) {
        if (value == null || !value.startsWith(prefix)
            || value.length() != prefix.length() + 64) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        for (int index = prefix.length(); index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f'))) {
                throw new IllegalArgumentException(label + " is invalid");
            }
        }
    }

    private static void requirePositiveFinite(double value, String label) {
        if (!(finite(value, label) > 0.0d)) {
            throw new IllegalArgumentException(label + " must be positive");
        }
    }

    private static double finite(double value, String label) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(label + " is not finite");
        }
        return value;
    }

    private static double positiveZero(double value) {
        return value == 0.0d ? 0.0d : value;
    }
}
