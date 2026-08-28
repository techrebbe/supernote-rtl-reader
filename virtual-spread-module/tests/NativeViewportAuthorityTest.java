import com.techrebbe.supernote.virtualspread.NativeViewportAuthority;

public final class NativeViewportAuthorityTest {
    private static final String DOCUMENT_ID =
        "inkbridge-doc-v1-"
        + "c9271098e6d98f7fff378c4d630dc9c179cf45cb5283f3559eee910e3afafeb4";
    private static final String VIEW_ID =
        "inkbridge-view-v1-"
        + "7cb2c2fda17d5510d33b0a97e702cbc66d5124735be45f810aef6053c1775f30";

    public static void main(String[] arguments) {
        normativePage143UsesTheExactNativePixelCanvas();
        nativeInsetsComeFromTheObservedRenderMatrix();
        nativeRotationIsPreserved();
        fittedGeometryGridStaysInsideTheNativeCanvas();
        tinyScaleOrientationRemainsStable();
        invalidOrUnstableGeometryFailsClosed();
        canonicalWireHasExactlyTheFrozenFields();
        System.out.println("NativeViewportAuthorityTest passed");
    }

    private static void normativePage143UsesTheExactNativePixelCanvas() {
        NativeViewportAuthority.Descriptor descriptor =
            NativeViewportAuthority.fromNativeRender(
                DOCUMENT_ID,
                VIEW_ID,
                1,
                864.0d,
                648.0d,
                1872,
                1404,
                1872,
                1404,
                new double[] {
                    (double) (float) (1872.0d / 864.0d),
                    0.0d,
                    0.0d,
                    (double) (float) (1404.0d / 648.0d),
                    0.0d,
                    0.0d
                },
                0.0d,
                0.0d
            );
        close(descriptor.spreadToNative[0], 1871.0d / 864.0d);
        exact(descriptor.spreadToNative[1], 0.0d);
        exact(descriptor.spreadToNative[2], 0.0d);
        close(descriptor.spreadToNative[3], -1403.0d / 648.0d);
        exact(descriptor.spreadToNative[4], 0.0d);
        exact(descriptor.spreadToNative[5], 1403.0d);
        NativeViewportAuthority.requireSpreadInsideNative(
            descriptor.spreadToNative,
            864.0d,
            648.0d,
            1872,
            1404
        );
    }

    private static void nativeInsetsComeFromTheObservedRenderMatrix() {
        NativeViewportAuthority.Descriptor descriptor =
            NativeViewportAuthority.fromNativeRender(
                DOCUMENT_ID,
                VIEW_ID,
                0,
                400.0d,
                600.0d,
                1872,
                1404,
                1872,
                1404,
                new double[] {2.0d, 0.0d, 0.0d, 2.0d, 0.0d, 0.0d},
                536.0d,
                102.0d
            );
        close(
            descriptor.spreadToNative[4],
            536.0d * 1871.0d / 1872.0d
        );
        close(
            descriptor.spreadToNative[5],
            1302.0d * 1403.0d / 1404.0d
        );
        NativeViewportAuthority.requireSpreadInsideNative(
            descriptor.spreadToNative,
            400.0d,
            600.0d,
            1872,
            1404
        );
    }

    private static void nativeRotationIsPreserved() {
        NativeViewportAuthority.Descriptor descriptor =
            NativeViewportAuthority.fromNativeRender(
                DOCUMENT_ID,
                VIEW_ID,
                2,
                648.0d,
                864.0d,
                1872,
                1404,
                1872,
                1404,
                new double[] {
                    0.0d,
                    1404.0d / 648.0d,
                    -1872.0d / 864.0d,
                    0.0d,
                    1872.0d,
                    0.0d
                },
                0.0d,
                0.0d
            );
        if (!(descriptor.spreadToNative[1] > 0.0d)
            || !(descriptor.spreadToNative[2] > 0.0d)) {
            throw new AssertionError("native rotation was not preserved");
        }
        NativeViewportAuthority.requireSpreadInsideNative(
            descriptor.spreadToNative,
            648.0d,
            864.0d,
            1872,
            1404
        );
    }

    private static void fittedGeometryGridStaysInsideTheNativeCanvas() {
        for (int index = 1; index <= 64; index++) {
            double spreadWidth = 320.0d + index * 7.0d;
            double spreadHeight = 500.0d + index * 3.0d;
            int nativeWidth = 1200 + index * 5;
            int nativeHeight = 1600 + index * 3;
            double scale = Math.min(
                (nativeWidth - 120.0d) / spreadWidth,
                (nativeHeight - 80.0d) / spreadHeight
            );
            double renderedWidth = spreadWidth * scale;
            double renderedHeight = spreadHeight * scale;
            double offsetX = (nativeWidth - renderedWidth) / 2.0d;
            double offsetY = (nativeHeight - renderedHeight) / 2.0d;
            NativeViewportAuthority.Descriptor descriptor =
                NativeViewportAuthority.fromNativeRender(
                    DOCUMENT_ID,
                    VIEW_ID,
                    index,
                    spreadWidth,
                    spreadHeight,
                    nativeWidth,
                    nativeHeight,
                    nativeWidth,
                    nativeHeight,
                    new double[] {
                        scale, 0.0d, 0.0d, scale, 0.0d, 0.0d
                    },
                    offsetX,
                    offsetY
                );
            NativeViewportAuthority.requireSpreadInsideNative(
                descriptor.spreadToNative,
                spreadWidth,
                spreadHeight,
                nativeWidth,
                nativeHeight
            );
        }
    }

    private static void tinyScaleOrientationRemainsStable() {
        NativeViewportAuthority.Descriptor descriptor =
            NativeViewportAuthority.Descriptor.validated(
                DOCUMENT_ID,
                VIEW_ID,
                0,
                1872,
                1404,
                new double[] {
                    0.0d, 1.0e-200d, -2.0e-200d, 0.0d, 17.0d, 23.0d
                }
            );
        if (!(descriptor.spreadToNative[1] > 0.0d)
            || !(descriptor.spreadToNative[2] < 0.0d)) {
            throw new AssertionError(
                "tiny stable orientation was not preserved"
            );
        }
    }

    private static void invalidOrUnstableGeometryFailsClosed() {
        for (int coefficient = 0; coefficient < 6; coefficient++) {
            final int changed = coefficient;
            expectFailure(new Runnable() {
                @Override
                public void run() {
                    double[] transform = new double[] {
                        1.0d, 0.0d, 0.0d, -1.0d, 0.0d, 1403.0d
                    };
                    transform[changed] = changed % 2 == 0
                        ? Double.NaN : Double.POSITIVE_INFINITY;
                    NativeViewportAuthority.Descriptor.validated(
                        DOCUMENT_ID,
                        VIEW_ID,
                        0,
                        1872,
                        1404,
                        transform
                    );
                }
            });
        }
        expectFailure(new Runnable() {
            @Override
            public void run() {
                NativeViewportAuthority.Descriptor.validated(
                    DOCUMENT_ID,
                    VIEW_ID,
                    0,
                    1872,
                    1404,
                    new double[] {1.0d, 0.0d, 1.0d, 1.0e-13d, 0.0d, 0.0d}
                );
            }
        });
        expectFailure(new Runnable() {
            @Override
            public void run() {
                NativeViewportAuthority.fromNativeRender(
                    DOCUMENT_ID,
                    VIEW_ID,
                    0,
                    864.0d,
                    648.0d,
                    1872,
                    1404,
                    1872,
                    1404,
                    new double[] {3.0d, 0.0d, 0.0d, 3.0d, 0.0d, 0.0d},
                    0.0d,
                    0.0d
                );
            }
        });
        expectFailure(new Runnable() {
            @Override
            public void run() {
                NativeViewportAuthority.fromNativeRender(
                    DOCUMENT_ID,
                    VIEW_ID,
                    0,
                    864.0d,
                    648.0d,
                    1872,
                    1404,
                    1872,
                    1404,
                    new double[] {
                        Double.NaN, 0.0d, 0.0d, 1.0d, 0.0d, 0.0d
                    },
                    0.0d,
                    0.0d
                );
            }
        });
    }

    private static void canonicalWireHasExactlyTheFrozenFields() {
        NativeViewportAuthority.Descriptor descriptor =
            NativeViewportAuthority.Descriptor.validated(
                DOCUMENT_ID,
                VIEW_ID,
                1,
                1872,
                1404,
                new double[] {
                    1871.0d / 864.0d,
                    0.0d,
                    0.0d,
                    -1403.0d / 648.0d,
                    0.0d,
                    1403.0d
                }
            );
        String expected = "{"
            + "\"schemaVersion\":1,"
            + "\"authority\":\"rtl-reader-native-viewport-v1\","
            + "\"documentId\":\"" + DOCUMENT_ID + "\","
            + "\"viewId\":\"" + VIEW_ID + "\","
            + "\"virtualPageIndex\":1,"
            + "\"nativePageSize\":[1872,1404],"
            + "\"spreadToNative\":["
            + Double.toString(1871.0d / 864.0d) + ",0.0,0.0,"
            + Double.toString(-1403.0d / 648.0d) + ",0.0,1403.0]}";
        if (!expected.equals(descriptor.canonicalJson())) {
            throw new AssertionError(
                "viewport wire changed\nexpected=" + expected
                + "\nactual=" + descriptor.canonicalJson()
            );
        }
        if (count(descriptor.canonicalJson(), ':') != 7) {
            throw new AssertionError("viewport wire contains extra fields");
        }
    }

    private static int count(String value, char character) {
        int count = 0;
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) == character) {
                count++;
            }
        }
        return count;
    }

    private static void close(double actual, double expected) {
        double tolerance = 1.0e-12d * Math.max(1.0d, Math.abs(expected));
        if (Math.abs(actual - expected) > tolerance) {
            throw new AssertionError(
                "expected " + expected + " but got " + actual
            );
        }
    }

    private static void exact(double actual, double expected) {
        if (Double.doubleToLongBits(actual)
            != Double.doubleToLongBits(expected)) {
            throw new AssertionError(
                "expected exact " + expected + " but got " + actual
            );
        }
    }

    private static void expectFailure(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected fail-closed rejection");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }
}
