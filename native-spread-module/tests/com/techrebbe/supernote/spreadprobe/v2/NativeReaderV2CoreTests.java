package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public final class NativeReaderV2CoreTests {
    private static int assertions;

    public static void main(String[] args) throws Exception {
        testAffineRoundTrips();
        testNativeProjectionGeometry();
        testNativePageTransform();
        testNativeDisplayTransform();
        testNativeDisplayTransformProperties();
        testNativeReaderV2LayoutFactory();
        testPairingMatrix();
        testV2ConfigAdmission();
        testStrictMarkerProperties();
        testNativeMarkPageInventory();
        testNativeSaveWitness();
        testNativeWriterGeometry();
        testTransactionalNavigationTargets();
        testV2CommittedMarkerClaim();
        testSnapshotAuthority();
        testGestureRouting();
        testActivationHappyPaths();
        testActivationRollbackAndStaleEvents();
        testActivationConcurrency();
        testSessionPublication();
        testControllerDirectPenActivation();
        testControllerFingerAndHover();
        testControllerRollbackAndHardDisable();
        testControllerTargetReadyBeforePenUp();
        testControllerSynchronousCallbacks();
        testControllerCallbackOrdering();
        testControllerPortFailures();
        testControllerInvalidInput();
        testControllerRetirementAndReplayTimeout();
        testControllerThreadConfinement();
        testFirmwarePortActivationAndReplay();
        testFirmwarePortDeferredSaveCallbacks();
        testFirmwarePortRollbackAndFailClosed();
        testFirmwarePortAuthorityAndThreadConfinement();
        testFirmwareSymbolContractDigest();
        System.out.println("NativeReaderV2CoreTests PASS assertions=" + assertions);
    }

    private static void testV2ConfigAdmission() {
        java.util.Properties properties = new java.util.Properties();
        check(NativeReaderV2Config.from(properties) == null,
            "ordinary marker cannot opt into v2");
        properties.setProperty("enabled", "true");
        properties.setProperty("direction", "rtl");
        check(NativeReaderV2Config.from(properties) == null,
            "legacy spread marker cannot opt into v2");

        properties.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        NativeReaderV2Config config = NativeReaderV2Config.from(properties);
        check(config.enabled, "explicit v2 marker enables v2");
        equal(SpreadPairing.Direction.RTL, config.direction,
            "v2 direction");
        check(!config.coverSeparate, "cover separate defaults off");
        check(!config.showDivider, "divider defaults off");
        check(!config.showHeader, "header defaults off");
        equal(NativeReaderV2Config.Sizing.FIT, config.sizing,
            "v2 sizing defaults to fit");

        properties.setProperty("enabled", "false");
        properties.setProperty("direction", "ltr");
        properties.setProperty("coverSeparate", "true");
        properties.setProperty("showDivider", "true");
        properties.setProperty("showHeader", "true");
        properties.setProperty("spreadSizing", "native_fill");
        config = NativeReaderV2Config.from(properties);
        check(!config.enabled, "explicit disabled marker remains disabled");
        equal(SpreadPairing.Direction.LTR, config.direction,
            "LTR parses exactly");
        check(config.coverSeparate, "cover parity parses exactly");
        check(config.showDivider, "divider parses exactly");
        check(config.showHeader, "header parses exactly");
        equal(NativeReaderV2Config.Sizing.NATIVE_FILL, config.sizing,
            "native fill parses exactly");

        for (String key : new String[] {
            "enabled", "coverSeparate", "showDivider", "showHeader"
        }) {
            java.util.Properties invalid = new java.util.Properties();
            invalid.setProperty(
                NativeReaderV2Config.ENGINE_KEY,
                NativeReaderV2Config.ENGINE_VALUE
            );
            invalid.setProperty(key, "TRUE");
            expectThrows(() -> NativeReaderV2Config.from(invalid),
                "noncanonical boolean rejected for " + key);
        }
        java.util.Properties invalidDirection = new java.util.Properties();
        invalidDirection.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        invalidDirection.setProperty("direction", "RTL");
        expectThrows(() -> NativeReaderV2Config.from(invalidDirection),
            "noncanonical direction rejected");
        java.util.Properties invalidSizing = new java.util.Properties();
        invalidSizing.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        invalidSizing.setProperty("spreadSizing", "fill");
        expectThrows(() -> NativeReaderV2Config.from(invalidSizing),
            "unknown sizing rejected");
    }

    private static void testNativePageTransform() {
        java.util.Properties properties = new java.util.Properties();
        properties.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        properties.setProperty("enabled", "true");
        NativeReaderV2Config config = NativeReaderV2Config.from(properties);
        NativeAuthority authority = authority(0, 1L, 1L);
        SpreadSnapshot snapshot = NativeReaderV2LayoutFactory.landscape(
            "doc", 1L, 1L, 10, 0,
            new RectD(0, 0, 1872, 1404),
            8.0,
            config,
            page -> new RectD(0, 0, 1404, 1872),
            authority,
            true
        );
        PageSlot slot = snapshot.slotForPage(0);
        Affine2D originalCtm = new Affine2D(
            2.5, 0.0, 0.0, 2.5, 3.0, 7.0
        );
        NativePageTransform transformed = NativePageTransform.from(
            originalCtm,
            41,
            57,
            slot
        );
        PointD pdf = new PointD(123.25, 321.75);
        PointD originalContent = originalCtm.map(pdf.x, pdf.y);
        PointD expected = slot.mapToScreen(
            originalContent.x + 41,
            originalContent.y + 57
        );
        PointD actualContent = transformed.ctm.map(pdf.x, pdf.y);
        PointD actual = new PointD(
            actualContent.x + transformed.offsetX,
            actualContent.y + transformed.offsetY
        );
        near(expected.x, actual.x, 0.51,
            "native PageInfo x shares compositor projection");
        near(expected.y, actual.y, 0.51,
            "native PageInfo y shares compositor projection");
        PointD roundTrip = transformed.revertCtm.map(
            actual.x - transformed.offsetX,
            actual.y - transformed.offsetY
        );
        near(pdf.x, roundTrip.x, 1.0e-8,
            "native PageInfo inverse x");
        near(pdf.y, roundTrip.y, 1.0e-8,
            "native PageInfo inverse y");

        expectThrows(() -> NativePageTransform.from(
            originalCtm,
            0,
            0,
            new PageSlot(
                0,
                PageSlot.Side.LEFT,
                new RectD(0, 0, 10, 10),
                new RectD(0, 0, 10, 10),
                new Affine2D(1, 0.1, 0, 1, 0, 0)
            )
        ), "native PageInfo rejects sheared compositor projection");
    }

    private static void testNativeDisplayTransform() {
        RectD full = new RectD(0, 0, 1404, 1872);
        RectD crop = new RectD(102, 213, 1187, 1639);
        Affine2D displayToOrigin = NativeDisplayTransform.displayToOrigin(
            crop,
            full
        );
        double stockScale = Math.min(
            full.width() / crop.width(),
            full.height() / crop.height()
        );
        int nativePaddingX = (int) ((full.width()
            - crop.width() * stockScale)
            * (crop.left / (full.width() - crop.width())));
        int nativePaddingY = (int) ((full.height()
            - crop.height() * stockScale)
            * (crop.top / (full.height() - crop.height())));
        PointD mapped = displayToOrigin.map(711.0, 934.0);
        near((711.0 - nativePaddingX) / stockScale + crop.left,
            mapped.x, 1.0e-9, "native crop x matches firmware formula");
        near((934.0 - nativePaddingY) / stockScale + crop.top,
            mapped.y, 1.0e-9, "native crop y matches firmware formula");
        equal(Affine2D.identity(),
            NativeDisplayTransform.displayToOrigin(full, full),
            "full-page display crop is identity");

        PageSlot slot = new PageSlot(
            0,
            PageSlot.Side.LEFT,
            crop,
            new RectD(0, 0, 936, 1404),
            new Affine2D(0.6, 0, 0, 0.6, -30, 20)
        );
        Affine2D originalCtm = new Affine2D(
            2.5, 0.0, 0.0, 2.5, 3.0, 7.0
        );
        NativePageTransform transformed = NativePageTransform.from(
            originalCtm,
            41,
            57,
            slot,
            displayToOrigin
        );
        PointD pdf = new PointD(123.25, 321.75);
        PointD original = originalCtm.map(pdf.x, pdf.y);
        PointD stockDisplay = new PointD(
            original.x + 41,
            original.y + 57
        );
        PointD expectedDisplay = slot.mapToScreen(
            stockDisplay.x,
            stockDisplay.y
        );
        // DocumentViewModel.checkLink()/select() apply mapToOrigin to the
        // physical touch before PageInfo.revertCtm. Model that exact firmware
        // pipeline rather than merely round-tripping the installed matrices.
        PointD expectedPostTrim = displayToOrigin.map(
            expectedDisplay.x,
            expectedDisplay.y
        );
        PointD installed = transformed.ctm.map(pdf.x, pdf.y);
        PointD installedPostTrim = new PointD(
            installed.x + transformed.offsetX,
            installed.y + transformed.offsetY
        );
        near(expectedPostTrim.x, installedPostTrim.x, 0.51,
            "cropped PageInfo x matches stock post-trim hit-test space");
        near(expectedPostTrim.y, installedPostTrim.y, 0.51,
            "cropped PageInfo y matches stock post-trim hit-test space");
        PointD wrongOrder = slot.mapToScreen(
            displayToOrigin.map(stockDisplay.x, stockDisplay.y).x,
            displayToOrigin.map(stockDisplay.x, stockDisplay.y).y
        );
        check(Math.abs(wrongOrder.x - installedPostTrim.x) > 10.0
                || Math.abs(wrongOrder.y - installedPostTrim.y) > 10.0,
            "crop fixture rejects pre-projection trim ordering");
        PointD roundTrip = transformed.revertCtm.map(
            expectedPostTrim.x - transformed.offsetX,
            expectedPostTrim.y - transformed.offsetY
        );
        near(pdf.x, roundTrip.x, 0.51,
            "cropped native PageInfo inverse x");
        near(pdf.y, roundTrip.y, 0.51,
            "cropped native PageInfo inverse y");

        Affine2D bitmapToOrigin =
            NativeDisplayTransform.croppedBitmapToOrigin(
                1085,
                1426,
                crop,
                full
            );
        near(crop.left, bitmapToOrigin.map(0, 0).x, 1.0e-9,
            "cropped bitmap begins at source left");
        near(crop.bottom, bitmapToOrigin.map(1085, 1426).y, 1.0e-9,
            "cropped bitmap ends at source bottom");
        expectThrows(() -> NativeDisplayTransform.displayToOrigin(
            new RectD(-1, 0, 100, 100),
            full
        ), "crop outside original page rejected");
    }

    private static void testNativeDisplayTransformProperties() {
        Random random = new Random(0x43524f505632L);
        RectD full = new RectD(0, 0, 1404, 1872);
        for (int index = 0; index < 5000; index++) {
            double left = random.nextDouble() * 350.0;
            double top = random.nextDouble() * 450.0;
            double right = 1054.0 + random.nextDouble() * 350.0;
            double bottom = 1422.0 + random.nextDouble() * 450.0;
            RectD crop = new RectD(left, top, right, bottom);
            Affine2D displayToOrigin =
                NativeDisplayTransform.displayToOrigin(crop, full);

            double projectionScale = Math.min(
                936.0 / crop.width(),
                1404.0 / crop.height()
            ) * (0.5 + random.nextDouble() * 0.5);
            double projectionX = (936.0 - crop.width()
                * projectionScale) / 2.0 - crop.left * projectionScale;
            double projectionY = (1404.0 - crop.height()
                * projectionScale) / 2.0 - crop.top * projectionScale;
            PageSlot slot = new PageSlot(
                0,
                PageSlot.Side.LEFT,
                crop,
                new RectD(0, 0, 936, 1404),
                new Affine2D(
                    projectionScale,
                    0.0,
                    0.0,
                    projectionScale,
                    projectionX,
                    projectionY
                )
            );

            double pageScale = 0.5 + random.nextDouble() * 3.0;
            double angle = random.nextDouble() * Math.PI * 2.0;
            double cosine = Math.cos(angle) * pageScale;
            double sine = Math.sin(angle) * pageScale;
            Affine2D originalCtm = new Affine2D(
                cosine,
                sine,
                -sine,
                cosine,
                random.nextDouble() * 50.0 - 25.0,
                random.nextDouble() * 50.0 - 25.0
            );
            int offsetX = random.nextInt(401) - 200;
            int offsetY = random.nextInt(401) - 200;
            NativePageTransform transformed = NativePageTransform.from(
                originalCtm,
                offsetX,
                offsetY,
                slot,
                displayToOrigin
            );

            double pdfX = random.nextDouble() * 800.0 - 400.0;
            double pdfY = random.nextDouble() * 800.0 - 400.0;
            PointD stockContent = originalCtm.map(pdfX, pdfY);
            PointD physical = slot.mapToScreen(
                stockContent.x + offsetX,
                stockContent.y + offsetY
            );
            PointD expectedPostTrim = displayToOrigin.map(
                physical.x,
                physical.y
            );
            PointD installedContent = transformed.ctm.map(pdfX, pdfY);
            PointD installedPostTrim = new PointD(
                installedContent.x + transformed.offsetX,
                installedContent.y + transformed.offsetY
            );
            near(expectedPostTrim.x, installedPostTrim.x, 0.51,
                "random cropped PageInfo forward x");
            near(expectedPostTrim.y, installedPostTrim.y, 0.51,
                "random cropped PageInfo forward y");

            PointD roundTrip = transformed.revertCtm.map(
                installedPostTrim.x - transformed.offsetX,
                installedPostTrim.y - transformed.offsetY
            );
            near(pdfX, roundTrip.x, 1.0e-7,
                "random cropped PageInfo inverse x");
            near(pdfY, roundTrip.y, 1.0e-7,
                "random cropped PageInfo inverse y");
        }
    }

    private static void testNativeMarkPageInventory() {
        check(!NativeMarkPageInventory.contains(
            Collections.emptyList(), 8, 0
        ), "empty native mark inventory proves an empty page");
        check(NativeMarkPageInventory.contains(
            Arrays.asList(1, 3, 8), 8, 2
        ), "one-based native mark inventory identifies a present page");
        check(!NativeMarkPageInventory.contains(
            Arrays.asList(1, 3, 8), 8, 3
        ), "one-based native mark inventory identifies an absent page");
        expectThrows(() -> NativeMarkPageInventory.contains(null, 8, 0),
            "missing native mark inventory rejected");
        expectThrows(() -> NativeMarkPageInventory.contains(
            Arrays.asList(1, 1), 8, 0
        ), "duplicate native mark page rejected");
        expectThrows(() -> NativeMarkPageInventory.contains(
            Arrays.asList(0), 8, 0
        ), "zero native mark page rejected");
        expectThrows(() -> NativeMarkPageInventory.contains(
            Arrays.asList(9), 8, 0
        ), "out-of-range native mark page rejected");
        expectThrows(() -> NativeMarkPageInventory.contains(
            Arrays.asList("1"), 8, 0
        ), "non-integer native mark page rejected");
        expectThrows(() -> NativeMarkPageInventory.contains(
            Collections.emptyList(), 0, 0
        ), "invalid page count rejected");
        expectThrows(() -> NativeMarkPageInventory.contains(
            Collections.emptyList(), 8, 8
        ), "invalid requested page rejected");
    }

    private static void testNativeSaveWitness() {
        Object note = new Object();
        NativeSaveWitness witness = new NativeSaveWitness();
        NativeSaveWitness.Token dirty = witness.begin(
            note, "/tmp/book.mark", 4, true
        );
        witness.observe(note, "/tmp/book.mark", 4, true, true);
        check(witness.finish(dirty), "dirty native save success witnessed");

        NativeSaveWitness.Token failed = witness.begin(
            note, "/tmp/book.mark", 4, true
        );
        witness.observe(note, "/tmp/book.mark", 4, true, false);
        check(!witness.finish(failed), "native save failure preserved");

        NativeSaveWitness.Token missing = witness.begin(
            note, "/tmp/book.mark", 4, true
        );
        check(!witness.finish(missing), "missing dirty save call rejected");

        NativeSaveWitness.Token clean = witness.begin(
            note, "/tmp/book.mark", 4, false
        );
        check(witness.finish(clean), "proven-clean no-op save accepted");

        NativeSaveWitness.Token unexpected = witness.begin(
            note, "/tmp/book.mark", 4, false
        );
        witness.observe(note, "/tmp/book.mark", 4, true, true);
        check(!witness.finish(unexpected),
            "unexpected save on clean page rejected");

        NativeSaveWitness.Token wrongPage = witness.begin(
            note, "/tmp/book.mark", 4, true
        );
        witness.observe(note, "/tmp/book.mark", 5, true, true);
        check(!witness.finish(wrongPage), "wrong-page save rejected");

        NativeSaveWitness.Token wrongNote = witness.begin(
            note, "/tmp/book.mark", 4, true
        );
        witness.observe(new Object(), "/tmp/book.mark", 4, true, true);
        check(!witness.finish(wrongNote), "wrong-note save rejected");

        NativeSaveWitness.Token duplicate = witness.begin(
            note, "/tmp/book.mark", 4, true
        );
        witness.observe(note, "/tmp/book.mark", 4, true, true);
        witness.observe(note, "/tmp/book.mark", 4, true, true);
        check(!witness.finish(duplicate), "duplicate native save rejected");

        NativeSaveWitness.Token aborted = witness.begin(
            note, "/tmp/book.mark", 4, true
        );
        witness.abort(aborted);
        check(!witness.active(), "aborted native save witness is retired");
        expectThrows(() -> witness.finish(aborted),
            "stale native save witness token rejected");
    }

    private static void testNativeWriterGeometry() {
        java.util.Properties properties = new java.util.Properties();
        properties.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        properties.setProperty("enabled", "true");
        NativeReaderV2Config config = NativeReaderV2Config.from(properties);
        NativeAuthority authority = authority(0, 1L, 7L);
        SpreadSnapshot right = NativeReaderV2LayoutFactory.landscape(
            "doc", 1L, 7L, 9, 0,
            new RectD(0, 0, 1872, 1404), 8.0,
            config,
            page -> new RectD(0, 0, 1404, 1872),
            authority,
            true
        );
        NativeWriterGeometry rightGeometry = NativeWriterGeometry.from(
            right,
            new RectD(0, 0, 1872, 1404),
            90
        );
        check(rightGeometry.rotation == 90, "right writer rotation retained");
        check(rightGeometry.viewWidth == 1872
            && rightGeometry.viewHeight == 1404,
            "writer uses physical canvas");
        check(rightGeometry.virtualWidth == 932
            && rightGeometry.virtualHeight == 1243,
            "right writer uses fitted page content");
        check(rightGeometry.originX == 0 && rightGeometry.originY == -81,
            "right writer origin derived from affine");

        NativeAuthority leftAuthority = authority(1, 1L, 8L);
        SpreadSnapshot left = NativeReaderV2LayoutFactory.landscape(
            "doc", 1L, 8L, 9, 1,
            new RectD(0, 0, 1872, 1404), 8.0,
            config,
            page -> new RectD(0, 0, 1404, 1872),
            leftAuthority,
            true
        );
        NativeWriterGeometry leftGeometry = NativeWriterGeometry.from(
            left,
            new RectD(0, 0, 1872, 1404),
            270
        );
        check(leftGeometry.originX == 940 && leftGeometry.originY == -81,
            "left writer origin derived from affine");
        near(0, leftGeometry.writableBounds.left, 0.0,
            "writer bounds left");
        near(81, leftGeometry.writableBounds.top, 0.0,
            "writer bounds top");
        near(932, leftGeometry.writableBounds.right, 0.0,
            "writer bounds right");
        near(1324, leftGeometry.writableBounds.bottom, 0.0,
            "writer bounds bottom");

        expectThrows(() -> NativeWriterGeometry.from(
            right,
            new RectD(0, 0, 1872, 1404),
            0
        ), "portrait presenter rotation rejected for spread writer");
        expectThrows(() -> NativeWriterGeometry.from(
            right,
            new RectD(1, 0, 1873, 1404),
            90
        ), "translated physical canvas rejected");
    }

    private static void testTransactionalNavigationTargets() {
        java.util.Properties properties = new java.util.Properties();
        properties.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        properties.setProperty("enabled", "true");
        NativeReaderV2Config rtl = NativeReaderV2Config.from(properties);
        SpreadSnapshot first = spread(0, 1, 1, true);
        equal(2, NativeReaderV2Navigation.swipeTarget(
            first, rtl, 200, 0
        ), "RTL right swipe advances to next transactional spread");
        equal(-1, NativeReaderV2Navigation.swipeTarget(
            first, rtl, -200, 0
        ), "RTL backward swipe stops at document start");
        equal(2, NativeReaderV2Navigation.offsetTarget(
            first, rtl, -1
        ), "native right-swipe offset advances RTL exactly once");
        equal(-1, NativeReaderV2Navigation.offsetTarget(
            first, rtl, 1
        ), "native left-swipe offset retreats RTL exactly once");
        equal(-1, NativeReaderV2Navigation.swipeTarget(
            first, rtl, 10, 100
        ), "vertical or sub-slop motion is not a page turn");

        properties.setProperty("direction", "ltr");
        NativeReaderV2Config ltr = NativeReaderV2Config.from(properties);
        equal(2, NativeReaderV2Navigation.swipeTarget(
            first, ltr, -200, 0
        ), "LTR left swipe advances to next transactional spread");
        equal(-1, NativeReaderV2Navigation.swipeTarget(
            first, ltr, 200, 0
        ), "LTR backward swipe stops at document start");
        equal(2, NativeReaderV2Navigation.offsetTarget(
            first, ltr, 1
        ), "native left-swipe offset advances LTR exactly once");
    }

    private static void testV2CommittedMarkerClaim() {
        String hash = repeat("ab", 32);
        java.util.Properties properties = committedV2Marker(hash);
        NativeReaderV2MarkerClaim claim = NativeReaderV2MarkerClaim.admit(
            properties,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        );
        equal("sha256:" + hash, claim.documentId,
            "claim uses immutable original PDF identity");
        check(claim.config.enabled, "committed marker enables v2");

        for (String key : new String[] {
            NativeReaderV2Config.ENGINE_KEY,
            "editable",
            "disposable",
            "managedBy",
            "mode",
            "transactionProtocol",
            "activationState",
            "backupVerified",
            "minimumModuleVersionCode",
            "activationToken",
            "documentPath",
            "documentLength",
            "documentSha256",
            "backupManifestPath",
            "backupManifestLength",
            "backupManifestSha256",
            "backupSnapshotPath",
            "markPath",
            "originalMarkPresent",
            "markLength",
            "markSha256",
            "backupCreatedAt"
        }) {
            java.util.Properties missing = committedV2Marker(hash);
            missing.remove(key);
            expectThrows(() -> NativeReaderV2MarkerClaim.admit(
                missing,
                "/storage/emulated/0/Document/book.pdf",
                123456L,
                hash
            ), "missing committed marker authority rejected for " + key);
        }

        for (String pending : new String[] {
            "pendingIntent",
            "previousMarkerPresent",
            "previousMarkerProtected",
            "previousMarkerLength",
            "previousMarkerSha256",
            "previousMarkerBase64"
        }) {
            java.util.Properties invalid = committedV2Marker(hash);
            invalid.setProperty(pending, "false");
            expectThrows(() -> NativeReaderV2MarkerClaim.admit(
                invalid,
                "/storage/emulated/0/Document/book.pdf",
                123456L,
                hash
            ), "pending activation authority rejected for " + pending);
        }

        java.util.Properties unknown = committedV2Marker(hash);
        unknown.setProperty("futureAuthority", "accepted-by-accident");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            unknown,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        ), "unknown committed marker authority rejected");

        java.util.Properties noncanonicalToken = committedV2Marker(hash);
        noncanonicalToken.setProperty(
            "activationToken",
            "12345678-1234-4234-8234-123456789ABC"
        );
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            noncanonicalToken,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        ), "noncanonical activation token rejected");

        java.util.Properties invalidBackupLength = committedV2Marker(hash);
        invalidBackupLength.setProperty("backupManifestLength", "0");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            invalidBackupLength,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        ), "empty recovery manifest rejected");

        java.util.Properties absentMark = committedV2Marker(hash);
        absentMark.setProperty("originalMarkPresent", "false");
        absentMark.setProperty("markLength", "0");
        absentMark.setProperty("markSha256", "ABSENT");
        NativeReaderV2MarkerClaim absentClaim = NativeReaderV2MarkerClaim.admit(
            absentMark,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        );
        check(!absentClaim.originalMarkPresent,
            "canonical absent-mark recovery authority accepted");
        java.util.Properties inconsistentAbsent = committedV2Marker(hash);
        inconsistentAbsent.setProperty("originalMarkPresent", "false");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            inconsistentAbsent,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        ), "absent mark cannot retain present-mark identity");

        java.util.Properties leadingZero = committedV2Marker(hash);
        leadingZero.setProperty("documentLength", "0123456");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            leadingZero,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        ), "noncanonical document length rejected");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            committedV2Marker(hash),
            "/storage/emulated/0/Document/book.pdf",
            123457L,
            hash
        ), "changed document length rejected");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            committedV2Marker(hash),
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            repeat("cd", 32)
        ), "changed document digest rejected");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            committedV2Marker(hash.toUpperCase(java.util.Locale.ROOT)),
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash.toUpperCase(java.util.Locale.ROOT)
        ), "noncanonical uppercase digest rejected");
        java.util.Properties olderContract = committedV2Marker(hash);
        olderContract.setProperty("minimumModuleVersionCode", "135");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            olderContract,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        ), "older companion contract rejected");
        java.util.Properties futureContract = committedV2Marker(hash);
        futureContract.setProperty("minimumModuleVersionCode", "137");
        expectThrows(() -> NativeReaderV2MarkerClaim.admit(
            futureContract,
            "/storage/emulated/0/Document/book.pdf",
            123456L,
            hash
        ), "future companion contract rejected");
    }

    private static void testStrictMarkerProperties() {
        java.util.Properties parsed = NativeReaderV2StrictProperties.parse(
            ("# generated\n"
                + "nativeReaderEngine=native-reader-v2\n"
                + "document\\ Path=/storage/emulated/0/Document/book.pdf\n"
                + "wrapped=first\\\n    second\n")
                .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)
        );
        equal("native-reader-v2", parsed.getProperty("nativeReaderEngine"),
            "strict properties parse ordinary key");
        equal("/storage/emulated/0/Document/book.pdf",
            parsed.getProperty("document Path"),
            "strict properties decode escaped key");
        equal("firstsecond", parsed.getProperty("wrapped"),
            "strict properties decode continuation");

        expectThrows(() -> NativeReaderV2StrictProperties.parse(
            "enabled=true\nenabled=false\n".getBytes(
                java.nio.charset.StandardCharsets.ISO_8859_1
            )
        ), "duplicate property rejected");
        expectThrows(() -> NativeReaderV2StrictProperties.parse(
            "document\\ Path=a\ndocument\\u0020Path=b\n".getBytes(
                java.nio.charset.StandardCharsets.ISO_8859_1
            )
        ), "escaped duplicate property rejected");
        expectThrows(() -> NativeReaderV2StrictProperties.parse(
            new byte[] { 'a', '=', 'b', 0, 'c' }
        ), "NUL property marker rejected");
        expectThrows(() -> NativeReaderV2StrictProperties.parse(new byte[0]),
            "empty marker rejected");
        expectThrows(() -> NativeReaderV2StrictProperties.parse(
            "key=value\\".getBytes(
                java.nio.charset.StandardCharsets.ISO_8859_1
            )
        ), "unterminated continuation rejected");
    }

    private static java.util.Properties committedV2Marker(String hash) {
        java.util.Properties properties = new java.util.Properties();
        properties.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        properties.setProperty("enabled", "true");
        properties.setProperty("direction", "rtl");
        properties.setProperty("coverSeparate", "false");
        properties.setProperty("showDivider", "false");
        properties.setProperty("showHeader", "false");
        properties.setProperty("spreadSizing", "fit");
        properties.setProperty("editable", "true");
        properties.setProperty("disposable", "false");
        properties.setProperty("managedBy", "supernote-rtl-reader");
        properties.setProperty("mode", NativeReaderV2MarkerClaim.MODE);
        properties.setProperty("transactionProtocol", "2");
        properties.setProperty("minimumModuleVersionCode", "136");
        properties.setProperty("activationState", "committed");
        properties.setProperty("backupVerified", "true");
        properties.setProperty(
            "activationToken",
            "12345678-1234-4234-8234-123456789abc"
        );
        properties.setProperty(
            "documentPath",
            "/storage/emulated/0/Document/book.pdf"
        );
        properties.setProperty("documentLength", "123456");
        properties.setProperty("documentSha256", hash);
        properties.setProperty(
            "backupManifestPath",
            "/storage/emulated/0/Document/.book.pdf.snspread-backup.properties"
        );
        properties.setProperty("backupManifestLength", "321");
        properties.setProperty("backupManifestSha256", repeat("b", 64));
        properties.setProperty(
            "backupSnapshotPath",
            "/storage/emulated/0/Document/.book.pdf.snspread-backup.mark"
        );
        properties.setProperty(
            "markPath",
            "/storage/emulated/0/Document/book.pdf.mark"
        );
        properties.setProperty("originalMarkPresent", "true");
        properties.setProperty("markLength", "654");
        properties.setProperty("markSha256", repeat("c", 64));
        properties.setProperty("backupCreatedAt", "1723456789000");
        return properties;
    }

    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder(value.length() * count);
        for (int index = 0; index < count; index++) result.append(value);
        return result.toString();
    }

    private static void testAffineRoundTrips() {
        Random random = new Random(0x5eed5eedL);
        for (int index = 0; index < 10000; index++) {
            double angle = random.nextDouble() * Math.PI * 2.0;
            double scaleX = 0.1 + random.nextDouble() * 4.0;
            double scaleY = 0.1 + random.nextDouble() * 4.0;
            double cos = Math.cos(angle);
            double sin = Math.sin(angle);
            Affine2D transform = new Affine2D(
                cos * scaleX,
                sin * scaleX,
                -sin * scaleY,
                cos * scaleY,
                random.nextDouble() * 10000.0 - 5000.0,
                random.nextDouble() * 10000.0 - 5000.0
            );
            double x = random.nextDouble() * 2000.0 - 1000.0;
            double y = random.nextDouble() * 2000.0 - 1000.0;
            PointD mapped = transform.map(x, y);
            PointD roundTrip = transform.derivedInverse().map(mapped.x, mapped.y);
            near(x, roundTrip.x, 1.0e-8, "affine x round trip");
            near(y, roundTrip.y, 1.0e-8, "affine y round trip");
        }
        expectThrows(() -> new Affine2D(
            Double.NaN, 0, 0, 1, 0, 0
        ), "non-finite affine");
        expectThrows(() -> new Affine2D(
            1, 1, 2, 2, 0, 0
        ), "singular affine");
        Affine2D android = Affine2D.fromAndroidMatrix(
            new double[] { 2, 0.5, 7, -0.25, 3, 11, 0, 0, 1 }
        );
        PointD androidPoint = android.map(4, 5);
        near(17.5, androidPoint.x, 1.0e-12, "Android matrix x");
        near(25.0, androidPoint.y, 1.0e-12, "Android matrix y");
        expectThrows(() -> Affine2D.fromAndroidMatrix(
            new double[] { 1, 0, 0, 0, 1, 0, 0.1, 0, 1 }
        ), "perspective matrix rejected");
        expectThrows(() -> new PageSlot(
            0,
            PageSlot.Side.FULL,
            new RectD(0, 0, 100, 100),
            new RectD(0, 0, 100, 100),
            new Affine2D(1, 0, 0, 1, 101, 0)
        ), "disjoint page transform");
        PageSlot diamond = new PageSlot(
            0,
            PageSlot.Side.FULL,
            new RectD(0, 0, 100, 100),
            new RectD(-100, -100, 200, 200),
            new Affine2D(1, 1, -1, 1, 50, -50)
        );
        check(diamond.contentBounds.contains(-40, -40),
            "rotated page bounding box includes diagnostic corner");
        check(!diamond.containsContent(-40, -40),
            "rotated page rejects point outside actual affine polygon");
    }

    private static void testNativeProjectionGeometry() {
        RectD source = new RectD(10, 20, 1010, 1420);
        RectD canvas = new RectD(0, 0, 1872, 1404);
        Affine2D rotatedNative = new Affine2D(
            0, -1, 1, 0, -20, 1010
        );
        PageSlot portrait = PageProjectionFactory.portrait(
            4, source, canvas, rotatedNative
        );
        equal(PageSlot.Side.FULL, portrait.side, "native portrait retained");
        PointD sourceRoundTrip = portrait.mapToSource(
            portrait.mapToScreen(417, 999).x,
            portrait.mapToScreen(417, 999).y
        );
        near(417, sourceRoundTrip.x, 1.0e-9, "portrait rotation round-trip x");
        near(999, sourceRoundTrip.y, 1.0e-9, "portrait rotation round-trip y");

        RectD left = new RectD(0, 0, 936, 1404);
        PageSlot projected = PageProjectionFactory.landscapeSlot(
            4, PageSlot.Side.LEFT, source, canvas, rotatedNative, left
        );
        RectD projectedBounds = projected.sourceToScreen.mapBounds(source);
        near(936, projectedBounds.width(), 1.0e-9,
            "wide rotated page uses full half width");
        near(668.5714285714286, projectedBounds.height(), 1.0e-9,
            "wide rotated page preserves aspect");
        near(0, projectedBounds.left, 1.0e-9, "wide page centered x");
        near((1404 - projectedBounds.height()) / 2.0,
            projectedBounds.top, 1.0e-9, "wide page centered y");
        RectD narrowSource = new RectD(0, 0, 400, 2000);
        Affine2D narrowNative = new Affine2D(
            0.6, 0, 0, 0.6, 816, 102
        );
        PageSlot narrow = PageProjectionFactory.landscapeSlot(
            5, PageSlot.Side.RIGHT, narrowSource, canvas, narrowNative,
            new RectD(936, 0, 1872, 1404)
        );
        RectD narrowBounds = narrow.sourceToScreen.mapBounds(narrowSource);
        near(1404, narrowBounds.height(), 1.0e-9,
            "narrow page uses full half height");
        near(280.8, narrowBounds.width(), 1.0e-9,
            "narrow page preserves aspect");
        near(936 + (936 - 280.8) / 2.0, narrowBounds.left, 1.0e-9,
            "narrow page centered");

        PageSlot filled = PageProjectionFactory.landscapeSlot(
            7,
            PageSlot.Side.RIGHT,
            new RectD(0, 0, 1404, 1872),
            new RectD(0, 0, 1872, 2496),
            new Affine2D(4.0 / 3.0, 0, 0, 4.0 / 3.0, 0, 0),
            new RectD(936, 0, 1872, 1404),
            PageProjectionFactory.Sizing.FILL
        );
        near(877.5, filled.contentBounds.left, 1.0e-9,
            "fill is centered across physical slot");
        near(1930.5, filled.contentBounds.right, 1.0e-9,
            "fill extends equally beyond physical slot");
        near(0.0, filled.contentBounds.top, 1.0e-9,
            "fill uses full slot height");
        near(1404.0, filled.contentBounds.bottom, 1.0e-9,
            "fill uses full slot height bottom");
        check(filled.containsContent(936, 702),
            "fill clipped left edge remains hittable");
        check(!filled.containsContent(935, 702),
            "fill cannot claim neighboring slot");

        expectThrows(() -> PageProjectionFactory.landscapeSlot(
            0,
            PageSlot.Side.LEFT,
            new RectD(0, 0, 100, 100),
            new RectD(0, 0, 100, 100),
            new Affine2D(1, 0, 0, 1, 20, 20),
            new RectD(0, 0, 50, 100)
        ), "cropped native source fails closed");
        expectThrows(() -> PageProjectionFactory.landscapeSlot(
            0,
            PageSlot.Side.LEFT,
            new RectD(0, 0, 100, 100),
            new RectD(0, 0, 100, 100),
            new Affine2D(1, 0, 0, 1, 0, 0),
            new RectD(-1, 0, 49, 100)
        ), "physical slot outside canvas fails closed");

        Random random = new Random(0x51a7f17L);
        for (int index = 0; index < 5000; index++) {
            double sourceLeft = random.nextDouble() * 200.0 - 100.0;
            double sourceTop = random.nextDouble() * 200.0 - 100.0;
            double width = 10.0 + random.nextDouble() * 3000.0;
            double height = 10.0 + random.nextDouble() * 3000.0;
            RectD randomSource = new RectD(
                sourceLeft,
                sourceTop,
                sourceLeft + width,
                sourceTop + height
            );
            double angle = random.nextDouble() * Math.PI * 2.0;
            Affine2D rotation = new Affine2D(
                Math.cos(angle),
                Math.sin(angle),
                -Math.sin(angle),
                Math.cos(angle),
                0,
                0
            );
            RectD rotated = rotation.mapBounds(randomSource);
            double nativeScale = Math.min(
                canvas.width() / rotated.width(),
                canvas.height() / rotated.height()
            ) * (0.5 + random.nextDouble() * 0.5);
            Affine2D toCanvas = new Affine2D(
                nativeScale,
                0,
                0,
                nativeScale,
                canvas.left + (canvas.width() - rotated.width() * nativeScale)
                    / 2.0 - rotated.left * nativeScale,
                canvas.top + (canvas.height() - rotated.height() * nativeScale)
                    / 2.0 - rotated.top * nativeScale
            );
            Affine2D nativeTransform = rotation.then(toCanvas);
            PageSlot randomSlot = PageProjectionFactory.landscapeSlot(
                index,
                PageSlot.Side.LEFT,
                randomSource,
                canvas,
                nativeTransform,
                left
            );
            RectD result = randomSlot.sourceToScreen.mapBounds(randomSource);
            near(left.left + left.width() / 2.0,
                result.left + result.width() / 2.0, 1.0e-7,
                "random projection centered x");
            near(left.top + left.height() / 2.0,
                result.top + result.height() / 2.0, 1.0e-7,
                "random projection centered y");
            check(result.width() <= left.width() + 1.0e-7
                && result.height() <= left.height() + 1.0e-7,
                "random projection fits slot");
            double sourceX = randomSource.left + random.nextDouble() * width;
            double sourceY = randomSource.top + random.nextDouble() * height;
            PointD screen = randomSlot.mapToScreen(sourceX, sourceY);
            PointD back = randomSlot.mapToSource(screen.x, screen.y);
            near(sourceX, back.x, 1.0e-7, "random projection inverse x");
            near(sourceY, back.y, 1.0e-7, "random projection inverse y");
        }
    }

    private static void testNativeReaderV2LayoutFactory() {
        final RectD[] pages = new RectD[] {
            new RectD(0, 0, 1404, 1872),
            new RectD(10, 20, 1010, 520),
            new RectD(-50, 40, 350, 2040),
            new RectD(0, 0, 2000, 2000),
            new RectD(0, 0, 612, 792),
        };
        NativeReaderV2LayoutFactory.PageGeometrySource geometry =
            new NativeReaderV2LayoutFactory.PageGeometrySource() {
                @Override
                public RectD sourceBox(int page) {
                    return pages[page];
                }
            };
        java.util.Properties properties = new java.util.Properties();
        properties.setProperty(
            NativeReaderV2Config.ENGINE_KEY,
            NativeReaderV2Config.ENGINE_VALUE
        );
        properties.setProperty("enabled", "true");
        properties.setProperty("coverSeparate", "true");
        NativeReaderV2Config config = NativeReaderV2Config.from(properties);
        NativeAuthority writer = authority(0, 1, 5);
        SpreadSnapshot cover = NativeReaderV2LayoutFactory.landscape(
            "doc", 1, 5, pages.length, 0,
            new RectD(0, 0, 1872, 1404), 0,
            config, geometry, writer, true
        );
        check(cover.leftOrFull.isBlank(), "cover left is virtual blank");
        equal(0, cover.right.sourcePageIndex, "cover remains on right");
        equal(0, cover.activePageIndex, "cover retains writer authority");

        SpreadSnapshot mixed = NativeReaderV2LayoutFactory.landscape(
            "doc", 1, 6, pages.length, 2,
            new RectD(0, 0, 1872, 1404), 8,
            config, geometry, authority(2, 1, 6), true
        );
        equal(1, mixed.right.sourcePageIndex, "RTL earlier page on right");
        equal(2, mixed.leftOrFull.sourcePageIndex,
            "RTL later page on left");
        check(mixed.leftOrFull.contentBounds.height()
                > mixed.leftOrFull.contentBounds.width(),
            "narrow page retains its geometry");
        check(!mixed.leftOrFull.screenBounds.overlaps(
                mixed.right.screenBounds),
            "divider keeps physical slots disjoint");

        properties.setProperty("spreadSizing", "native_fill");
        config = NativeReaderV2Config.from(properties);
        SpreadSnapshot filled = NativeReaderV2LayoutFactory.landscape(
            "doc", 1, 7, pages.length, 4,
            new RectD(0, 0, 1872, 1404), 0,
            config, geometry, authority(4, 1, 7), true
        );
        PageSlot active = filled.slotForPage(4);
        check(active.contentBounds.width() >= active.screenBounds.width(),
            "native fill covers active slot width");
        check(active.contentBounds.height() >= active.screenBounds.height(),
            "native fill covers active slot height");
        check(active.containsContent(
                active.screenBounds.left + 1,
                active.screenBounds.top + 1
            ), "native fill corner maps inside source");

        properties.setProperty("enabled", "false");
        NativeReaderV2Config disabled = NativeReaderV2Config.from(properties);
        expectThrows(() -> NativeReaderV2LayoutFactory.landscape(
            "doc", 1, 8, pages.length, 4,
            new RectD(0, 0, 1872, 1404), 0,
            disabled, geometry, authority(4, 1, 8), true
        ), "disabled config cannot build spread authority");
    }

    private static void testPairingMatrix() {
        for (int pageCount = 1; pageCount <= 40; pageCount++) {
            for (int page = 0; page < pageCount; page++) {
                for (SpreadPairing.Direction direction
                    : SpreadPairing.Direction.values()) {
                    for (boolean cover : new boolean[] { false, true }) {
                        SpreadPairing.Pair pair = SpreadPairing.forPage(
                            page,
                            pageCount,
                            direction,
                            cover
                        );
                        check(pair.contains(page), "pair must contain focus");
                        check(pair.leftPage < pageCount, "left bound");
                        check(pair.rightPage < pageCount, "right bound");
                        check(pair.leftPage >= -1 && pair.rightPage >= -1,
                            "blank sentinel only");
                        if (pair.leftPage >= 0 && pair.rightPage >= 0) {
                            check(Math.abs(pair.leftPage - pair.rightPage) == 1,
                                "paired pages must be adjacent");
                        }
                        if (direction == SpreadPairing.Direction.RTL
                            && pair.leftPage >= 0 && pair.rightPage >= 0) {
                            check(pair.leftPage > pair.rightPage,
                                "RTL physical order");
                        }
                        if (direction == SpreadPairing.Direction.LTR
                            && pair.leftPage >= 0 && pair.rightPage >= 0) {
                            check(pair.leftPage < pair.rightPage,
                                "LTR physical order");
                        }
                    }
                }
            }
        }
        SpreadPairing.Pair cover = SpreadPairing.forPage(
            0, 10, SpreadPairing.Direction.RTL, true
        );
        equal(-1, cover.leftPage, "RTL cover blank on left");
        equal(0, cover.rightPage, "RTL cover on right");
        SpreadPairing.Pair next = SpreadPairing.forPage(
            1, 10, SpreadPairing.Direction.RTL, true
        );
        equal(2, next.leftPage, "page 3 on left");
        equal(1, next.rightPage, "page 2 on right");
    }

    private static void testSnapshotAuthority() {
        SpreadSnapshot spread = spread(1, 1, 1, true);
        check(spread.writerReady, "fixture writer ready");
        equal(1, spread.slotAt(100, 500).sourcePageIndex, "left hit");
        equal(0, spread.slotAt(1200, 500).sourcePageIndex, "right hit");
        check(spread.slotAt(935.999, 500).sourcePageIndex == 1,
            "divider boundary remains left");
        check(spread.slotAt(936.0, 500).sourcePageIndex == 0,
            "half-open boundary becomes right");
        expectThrows(() -> new SpreadSnapshot(
            "doc", 1, 1, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), rightSlot(0), authority(0, 1, 1), true
        ), "stale writer page");
        expectThrows(() -> new SpreadSnapshot(
            "doc", 1, 1, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), leftSlot(0), authority(1, 1, 1), true
        ), "duplicate physical side");
        expectThrows(() -> new SpreadSnapshot(
            "doc", 1, 1, 10, 1, SpreadSnapshot.Mode.SPREAD,
            new PageSlot(
                1,
                PageSlot.Side.LEFT,
                new RectD(0, 0, 1000, 1400),
                new RectD(936, 0, 1872, 1404),
                new Affine2D(0.936, 0, 0, 0.936, 936, 46.8)
            ),
            new PageSlot(
                0,
                PageSlot.Side.RIGHT,
                new RectD(0, 0, 1000, 1400),
                new RectD(0, 0, 936, 1404),
                new Affine2D(0.936, 0, 0, 0.936, 0, 46.8)
            ),
            authority(1, 1, 1),
            true
        ), "physical left/right slot order cannot be reversed");
        SpreadSnapshot cover = new SpreadSnapshot(
            "doc", 1, 2, 10, 0, SpreadSnapshot.Mode.SPREAD,
            PageSlot.blank(PageSlot.Side.LEFT, new RectD(0, 0, 936, 1404)),
            rightSlot(0), authority(0, 1, 2), true
        );
        check(cover.leftOrFull.isBlank(), "cover blank is explicit");
        check(cover.slotAt(100, 500).isBlank(), "blank occupies physical slot");
        expectThrows(() -> cover.leftOrFull.mapToSource(100, 500),
            "blank has no inverse transform");
        expectThrows(() -> new SpreadSnapshot(
            "doc", 1, 2, 10, 0, SpreadSnapshot.Mode.SPREAD,
            PageSlot.blank(PageSlot.Side.LEFT, new RectD(0, 0, 936, 1404)),
            rightSlot(0), authority(0, 1, 2), false
        ), "unready authority rejected");
    }

    private static void testGestureRouting() {
        SpreadSnapshot spread = spread(1, 1, 1, true);
        GestureRouter router = new GestureRouter();
        List<RectD> chrome = Collections.singletonList(
            new RectD(0, 0, 1872, 100)
        );
        GestureRouter.Token toolbar = router.begin(
            spread, 0, 100, 50, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.NATIVE_CHROME, toolbar.route,
            "chrome wins at DOWN");
        check(router.current(toolbar.id, 0) == toolbar,
            "route remains latched while moving out of chrome");
        check(router.finish(toolbar.id, 0), "finish chrome gesture");

        GestureRouter.Token active = router.begin(
            spread, 0, 100, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.ACTIVE_DOCUMENT, active.route,
            "active pen native");
        check(router.finish(active.id, 0), "finish active gesture");

        GestureRouter.Token unknown = router.begin(
            spread, 0, 100, 500, GestureRouter.Tool.UNKNOWN, chrome
        );
        equal(GestureRouter.Route.BLOCKED, unknown.route,
            "unknown document tool fails closed");
        check(router.finish(unknown.id, 0), "finish unknown gesture");

        GestureRouter.Token inactiveFinger = router.begin(
            spread, 0, 1200, 500, GestureRouter.Tool.FINGER, chrome
        );
        equal(GestureRouter.Route.ACTIVATE_AND_REPLAY_HIT,
            inactiveFinger.route, "inactive finger activation");
        check(router.finish(inactiveFinger.id, 0), "finish inactive finger");

        GestureRouter.Token inactivePen = router.begin(
            spread, 0, 1200, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.ACTIVATE_AND_DRAIN_PEN,
            inactivePen.route, "inactive pen activation");
        SpreadSnapshot newer = spread(1, 1, 2, true);
        check(!router.authorityCurrent(inactivePen, newer),
            "layout replacement invalidates gesture authority");
        check(!router.finish(inactivePen.id, 1), "wrong pointer cannot finish");
        check(router.finish(inactivePen.id, 0), "right pointer finishes");

        GestureRouter.Token hiddenToolbar = router.begin(
            spread, 0, 100, 50, GestureRouter.Tool.STYLUS,
            Collections.<RectD>emptyList()
        );
        equal(GestureRouter.Route.ACTIVE_DOCUMENT, hiddenToolbar.route,
            "hidden toolbar rectangle is document again");
        check(router.finish(hiddenToolbar.id, 0), "finish hidden-toolbar pen");

        GestureRouter.Token letterboxPen = router.begin(
            spread, 0, 100, 10, GestureRouter.Tool.STYLUS,
            Collections.<RectD>emptyList()
        );
        equal(GestureRouter.Route.BLOCKED, letterboxPen.route,
            "pen cannot write in page letterbox");
        router.retire();
        GestureRouter.Token letterboxFinger = router.begin(
            spread, 0, 1200, 10, GestureRouter.Tool.FINGER,
            Collections.<RectD>emptyList()
        );
        equal(GestureRouter.Route.ACTIVATE_AND_REPLAY_HIT,
            letterboxFinger.route,
            "finger may activate a physical side through its margin");
        router.retire();

        SpreadSnapshot blocked = spread(1, 1, 1, false);
        GestureRouter.Token noWriter = router.begin(
            blocked, 0, 100, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.BLOCKED, noWriter.route,
            "unverified active writer fails closed");
        router.retire();
        GestureRouter.Token blockedInactive = router.begin(
            blocked, 0, 1200, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.BLOCKED, blockedInactive.route,
            "unverified source cannot activate inactive page");
        router.retire();
        SpreadSnapshot cover = new SpreadSnapshot(
            "doc", 1, 2, 10, 0, SpreadSnapshot.Mode.SPREAD,
            PageSlot.blank(PageSlot.Side.LEFT, new RectD(0, 0, 936, 1404)),
            rightSlot(0), authority(0, 1, 2), true
        );
        GestureRouter.Token blank = router.begin(
            cover, 0, 100, 500, GestureRouter.Tool.STYLUS, chrome
        );
        equal(GestureRouter.Route.BLOCKED, blank.route,
            "blank page never owns input");
        router.retire();
        equal(GestureRouter.Route.ACTIVATE_AND_DRAIN_PEN,
            router.classifyHover(spread, 1200, 500,
                GestureRouter.Tool.STYLUS, chrome),
            "inactive hover preactivates");
    }

    private static void testActivationHappyPaths() {
        SpreadSnapshot spread = spread(1, 1, 1, true);
        ActivationMachine machine = new ActivationMachine();
        machine.initialize(spread);
        ActivationMachine.Token token = machine.begin(
            spread, 0, ActivationMachine.CompletionMode.REPLAY_INPUT
        );
        check(token != null, "activation begins");
        status(machine, ActivationMachine.State.SOURCE_SAVING, 1, false);
        check(machine.sourceSaved(token), "source save accepted");
        check(!machine.targetLoaded(token, 1), "wrong load page rejected");
        check(machine.targetLoaded(token, 0), "target load accepted");
        check(!machine.targetVerified(token, authority(0, 1, 1)),
            "same-generation target authority rejected");
        check(!machine.targetVerified(token, authority(1, 1, 2)),
            "wrong writer page rejected");
        check(machine.targetVerified(token, authority(0, 1, 2)),
            "target authority verified");
        status(machine, ActivationMachine.State.TARGET_PUBLISHING, 0, false);
        SpreadSnapshot targetSnapshot = spread(0, 1, 2, true);
        check(machine.targetPublished(token, targetSnapshot),
            "target snapshot published atomically");
        status(machine, ActivationMachine.State.REPLAYING, 0, false);
        check(machine.replayComplete(token, authority(0, 1, 2)),
            "replay completion accepted");
        status(machine, ActivationMachine.State.ACTIVE, 0, true);

        ActivationMachine.Token noReplay = machine.begin(
            targetSnapshot, 1, ActivationMachine.CompletionMode.IMMEDIATE
        );
        check(noReplay != null, "second activation begins");
        check(machine.sourceSaved(noReplay), "second source saved");
        check(machine.targetLoaded(noReplay, 1), "second target loaded");
        check(machine.targetVerified(noReplay, authority(1, 1, 3)),
            "no-replay target verifies");
        check(machine.targetPublished(noReplay, spread(1, 1, 3, true)),
            "no-replay activation publishes");
        status(machine, ActivationMachine.State.ACTIVE, 1, true);
    }

    private static void testActivationRollbackAndStaleEvents() {
        SpreadSnapshot spread = spread(1, 2, 5, true);
        ActivationMachine machine = new ActivationMachine();
        machine.initialize(spread);
        ActivationMachine.Token token = machine.begin(
            spread, 0, ActivationMachine.CompletionMode.IMMEDIATE
        );
        check(machine.sourceSaved(token), "rollback source saved");
        check(machine.fail(token), "failure starts rollback");
        check(!machine.rollbackVerified(token, authority(1, 2, 4)),
            "stale layout rollback rejected");
        check(machine.rollbackVerified(token, authority(1, 2, 6)),
            "source rollback verified");
        status(machine, ActivationMachine.State.ROLLBACK_PUBLISHING, 1, false);
        SpreadSnapshot recovered = spread(1, 2, 6, true);
        check(machine.rollbackPublished(token, recovered),
            "rollback snapshot published atomically");
        status(machine, ActivationMachine.State.ACTIVE, 1, true);
        check(!machine.sourceSaved(token), "retired callback rejected");

        ActivationMachine.Token doomed = machine.begin(
            recovered, 0, ActivationMachine.CompletionMode.IMMEDIATE
        );
        check(doomed != null && machine.fail(doomed), "second failure");
        check(machine.rollbackFailed(doomed), "rollback failure disables");
        status(machine, ActivationMachine.State.DISABLED, 1, false);
        check(machine.begin(
            spread, 0, ActivationMachine.CompletionMode.IMMEDIATE
        ) == null,
            "disabled machine cannot reactivate silently");
    }

    private static void testActivationConcurrency() throws Exception {
        SpreadSnapshot spread = spread(1, 3, 1, true);
        ActivationMachine machine = new ActivationMachine();
        machine.initialize(spread);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger();
        Thread[] threads = new Thread[16];
        for (int index = 0; index < threads.length; index++) {
            threads[index] = new Thread(() -> {
                try {
                    start.await();
                    if (machine.begin(
                        spread,
                        0,
                        ActivationMachine.CompletionMode.IMMEDIATE
                    ) != null) {
                        winners.incrementAndGet();
                    }
                } catch (InterruptedException exception) {
                    throw new AssertionError(exception);
                }
            });
            threads[index].start();
        }
        start.countDown();
        for (Thread thread : threads) {
            thread.join();
        }
        equal(1, winners.get(), "exactly one activation owns writer");
    }

    private static void testSessionPublication() {
        SpreadSession session = new SpreadSession();
        SpreadSnapshot first = spread(1, 1, 1, true);
        check(session.publish(first), "first snapshot publishes");
        GestureRouter.Token token = session.gestures().begin(
            first, 0, 100, 500, GestureRouter.Tool.STYLUS,
            Collections.<RectD>emptyList()
        );
        check(session.gestures().authorityCurrent(token, first),
            "published gesture current");
        check(!session.publish(spread(1, 1, 1, true)),
            "same generation rejected");
        SpreadSnapshot second = spread(1, 1, 2, true);
        check(!session.publish(second),
            "layout publication cannot cut through a native contact");
        check(session.gestures().current(token.id, 0) == token,
            "rejected layout preserves down-time route");
        check(session.gestures().finish(token.id, 0),
            "native contact finishes before layout publication");
        check(session.publish(second), "newer layout publishes after terminal");
        check(!session.publish(spread(1, 1, 1, true)),
            "older layout rejected");
        status(session.activation(), ActivationMachine.State.ACTIVE, 1, true);
        SpreadSnapshot wrongDocument = new SpreadSnapshot(
            "other", 1, 3, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), rightSlot(0),
            new NativeAuthority("other", 1, 3, 1, 11, 12, 13, 14, 1),
            true
        );
        check(!session.publish(wrongDocument),
            "session rejects document replacement");
        SpreadSnapshot wrongActivity = new SpreadSnapshot(
            "doc", 2, 3, 10, 1, SpreadSnapshot.Mode.SPREAD,
            leftSlot(1), rightSlot(0), authority(1, 2, 3), true
        );
        check(!session.publish(wrongActivity),
            "session rejects activity replacement");
        session.retire();
        check(session.snapshot() == null, "retire clears snapshot");
        status(session.activation(), ActivationMachine.State.DISABLED, -1, false);

        SpreadSession activationSession = new SpreadSession();
        SpreadSnapshot activationStart = spread(1, 7, 1, true);
        check(activationSession.publish(activationStart),
            "activation session initialized");
        ActivationMachine.Token activation = activationSession.activation()
            .begin(
                activationStart,
                0,
                ActivationMachine.CompletionMode.REPLAY_INPUT
            );
        check(activationSession.activation().sourceSaved(activation),
            "session activation source saved");
        check(activationSession.activation().targetLoaded(activation, 0),
            "session activation target loaded");
        check(activationSession.activation().targetVerified(
            activation, authority(0, 7, 2)
        ), "session target verified");
        check(!activationSession.publish(spread(0, 7, 2, true)),
            "ordinary publication cannot bypass transaction");
        SpreadSnapshot activated = spread(0, 7, 2, true);
        check(activationSession.publishActivated(activation, activated),
            "transaction publishes exact verified snapshot");
        equal(0, activationSession.snapshot().activePageIndex,
            "activated source is published");
        status(activationSession.activation(),
            ActivationMachine.State.REPLAYING, 0, false);
        check(activationSession.activation().replayComplete(
            activation, authority(0, 7, 2)
        ), "session buffered replay finishes");
        status(activationSession.activation(),
            ActivationMachine.State.ACTIVE, 0, true);
    }

    private static void testControllerDirectPenActivation() {
        SpreadSession session = initializedSession(1, 10, 1);
        FakePort port = new FakePort();
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        NativeReaderController.DownDecision down = controller.onDown(
            0, 1200, 500, 0.6, 100,
            GestureRouter.Tool.STYLUS, Collections.<RectD>emptyList()
        );
        equal(NativeReaderController.InputResult.CONSUMED, down.result,
            "inactive direct pen consumed");
        check(down.gestureTokenId > 0, "direct pen token published");
        equal(Arrays.asList("freeze", "save"), port.calls,
            "activation freezes before source save");
        ActivationMachine.Token token = port.lastToken;
        equal(NativeReaderController.InputResult.CONSUMED,
            controller.onMotion(
                down.gestureTokenId, 0, GestureAction.MOVE,
                100, 500, 0.7, 110
            ), "cross-divider pen move consumed");
        equal(NativeReaderController.InputResult.CONSUMED,
            controller.onMotion(
                down.gestureTokenId, 0, GestureAction.UP,
                100, 500, 0.0, 120
            ), "cross-divider pen terminal consumed");
        controller.onSourceSaveComplete(token, true);
        equal(Arrays.asList("freeze", "save", "disableWriter", "load"),
            port.calls, "save precedes writer disable and load");
        controller.onTargetLoadComplete(token, 0, true);
        controller.onTargetReady(
            token,
            authority(0, 10, 2),
            spread(0, 10, 2, true)
        );
        equal("release", port.calls.get(port.calls.size() - 1),
            "input releases only after dropped contact drains");
        check(!port.calls.contains("replayFinger"),
            "direct pen contact is never fabricated as native input");
        equal(0, session.snapshot().activePageIndex,
            "direct pen activation publishes target page");
        status(session.activation(), ActivationMachine.State.ACTIVE, 0, true);
    }

    private static void testControllerFingerAndHover() {
        SpreadSession swipeSession = initializedSession(1, 11, 1);
        FakePort swipePort = new FakePort();
        NativeReaderController swipeController = new NativeReaderController(
            swipeSession, swipePort
        );
        NativeReaderController.DownDecision swipe = swipeController.onDown(
            0, 1200, 500, 0, 0,
            GestureRouter.Tool.FINGER, Collections.<RectD>emptyList()
        );
        equal(NativeReaderController.InputResult.CONSUMED, swipe.result,
            "inactive finger held for classification");
        equal(0, swipePort.calls.size(),
            "finger down does not activate before tap/swipe decision");
        swipeController.onMotion(
            swipe.gestureTokenId, 0, GestureAction.MOVE,
            1100, 500, 0, 10
        );
        swipeController.onMotion(
            swipe.gestureTokenId, 0, GestureAction.UP,
            1050, 500, 0, 20
        );
        equal(Arrays.asList("navigateTarget", "freeze", "save"),
            swipePort.calls,
            "finger swipe uses the writer-transfer transaction");

        SpreadSession tapSession = initializedSession(1, 11, 1);
        FakePort tapPort = new FakePort();
        NativeReaderController tapController = new NativeReaderController(
            tapSession, tapPort
        );
        NativeReaderController.DownDecision tap = tapController.onDown(
            0, 1200, 500, 0, 30,
            GestureRouter.Tool.FINGER, Collections.<RectD>emptyList()
        );
        tapController.onMotion(
            tap.gestureTokenId, 0, GestureAction.UP,
            1200, 500, 0, 40
        );
        equal(Arrays.asList("freeze", "save"), tapPort.calls,
            "finger tap begins activation after UP");
        ActivationMachine.Token tapToken = tapPort.lastToken;
        tapController.onSourceSaveComplete(tapToken, true);
        tapController.onTargetLoadComplete(tapToken, 0, true);
        tapController.onTargetReady(
            tapToken,
            authority(0, 11, 2),
            spread(0, 11, 2, true)
        );
        equal("replayFinger", tapPort.calls.get(tapPort.calls.size() - 1),
            "finger hit replays after verified activation");
        check(tapPort.replayedFinger != null,
            "finger replay uses preserved source coordinate");
        tapController.onReplayComplete(tapToken, true);
        equal("release", tapPort.calls.get(tapPort.calls.size() - 1),
            "finger activation releases after replay");

        SpreadSession hoverSession = initializedSession(1, 12, 1);
        FakePort hoverPort = new FakePort();
        NativeReaderController hoverController = new NativeReaderController(
            hoverSession, hoverPort
        );
        check(!hoverController.onInactiveHover(
            1200,
            10,
            Collections.<RectD>emptyList()
        ), "letterbox hover does not activate");
        check(!hoverController.onInactiveHover(
            1200,
            50,
            Collections.singletonList(new RectD(900, 0, 1500, 100))
        ), "native chrome hover does not activate");
        check(hoverController.onInactiveHover(
            1200,
            500,
            Collections.<RectD>emptyList()
        ),
            "inactive hover starts preactivation");
        ActivationMachine.Token hoverToken = hoverPort.lastToken;
        hoverController.onSourceSaveComplete(hoverToken, true);
        hoverController.onTargetLoadComplete(hoverToken, 0, true);
        hoverController.onTargetReady(
            hoverToken,
            authority(0, 12, 2),
            spread(0, 12, 2, true)
        );
        check(!hoverPort.calls.contains("replayPen")
            && !hoverPort.calls.contains("replayFinger"),
            "hover activation has no synthetic input");
        equal("release", hoverPort.calls.get(hoverPort.calls.size() - 1),
            "hover releases on target publication");

        SpreadSession marginSession = initializedSession(1, 16, 1);
        FakePort marginPort = new FakePort();
        NativeReaderController marginController = new NativeReaderController(
            marginSession, marginPort
        );
        NativeReaderController.DownDecision margin = marginController.onDown(
            0, 1200, 10, 0, 0,
            GestureRouter.Tool.FINGER, Collections.<RectD>emptyList()
        );
        marginController.onMotion(
            margin.gestureTokenId, 0, GestureAction.UP,
            1200, 10, 0, 10
        );
        ActivationMachine.Token marginToken = marginPort.lastToken;
        marginController.onSourceSaveComplete(marginToken, true);
        marginController.onTargetLoadComplete(marginToken, 0, true);
        marginController.onTargetReady(
            marginToken,
            authority(0, 16, 2),
            spread(0, 16, 2, true)
        );
        check(!marginPort.calls.contains("replayFinger"),
            "letterbox tap activates without replaying an out-of-page hit");
        equal("release", marginPort.calls.get(marginPort.calls.size() - 1),
            "letterbox activation releases after publication");
    }

    private static void testControllerRollbackAndHardDisable() {
        SpreadSession rollbackSession = initializedSession(1, 13, 1);
        FakePort rollbackPort = new FakePort();
        NativeReaderController rollbackController = new NativeReaderController(
            rollbackSession, rollbackPort
        );
        NativeReaderController.DownDecision down = rollbackController.onDown(
            0, 1200, 500, 0.5, 0,
            GestureRouter.Tool.STYLUS, Collections.<RectD>emptyList()
        );
        ActivationMachine.Token token = rollbackPort.lastToken;
        rollbackController.onSourceSaveComplete(token, false);
        equal("rollback", rollbackPort.calls.get(rollbackPort.calls.size() - 1),
            "source-save failure requests rollback");
        rollbackController.onRollbackReady(
            token,
            authority(1, 13, 2),
            spread(1, 13, 2, true)
        );
        equal("release", rollbackPort.calls.get(rollbackPort.calls.size() - 1),
            "verified rollback releases input");
        equal(1, rollbackSession.snapshot().activePageIndex,
            "rollback republishes source");
        equal(NativeReaderController.InputResult.BLOCKED,
            rollbackController.onMotion(
                down.gestureTokenId, 0, GestureAction.UP,
                1200, 500, 0, 10
            ), "retired activation gesture cannot mutate rollback");

        SpreadSession cancelSession = initializedSession(1, 14, 1);
        FakePort cancelPort = new FakePort();
        NativeReaderController cancelController = new NativeReaderController(
            cancelSession, cancelPort
        );
        NativeReaderController.DownDecision cancelled = cancelController.onDown(
            0, 1200, 500, 0.5, 0,
            GestureRouter.Tool.STYLUS, Collections.<RectD>emptyList()
        );
        ActivationMachine.Token cancelToken = cancelPort.lastToken;
        cancelController.onMotion(
            cancelled.gestureTokenId, 0, GestureAction.CANCEL,
            1210, 510, 0.0, 2
        );
        cancelController.onSourceSaveComplete(cancelToken, true);
        cancelController.onTargetLoadComplete(cancelToken, 0, true);
        cancelController.onTargetReady(
            cancelToken,
            authority(0, 14, 2),
            spread(0, 14, 2, true)
        );
        equal("release", cancelPort.calls.get(cancelPort.calls.size() - 1),
            "cancelled direct contact drains without replay or rollback");
    }

    private static void testControllerTargetReadyBeforePenUp() {
        SpreadSession session = initializedSession(1, 20, 1);
        FakePort port = new FakePort();
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        NativeReaderController.DownDecision down = controller.onDown(
            0, 1200, 500, 0.5, 0,
            GestureRouter.Tool.STYLUS, Collections.<RectD>emptyList()
        );
        ActivationMachine.Token token = port.lastToken;
        controller.onSourceSaveComplete(token, true);
        controller.onTargetLoadComplete(token, 0, true);
        controller.onTargetReady(
            token,
            authority(0, 20, 2),
            spread(0, 20, 2, true)
        );
        equal(ActivationMachine.State.DRAINING_CONTACT,
            session.activation().status().state,
            "target publication waits for physical pen terminal");
        equal(NativeReaderController.InputResult.CONSUMED,
            controller.onMotion(
                down.gestureTokenId, 0, GestureAction.UP,
                1210, 510, 0, 20
            ), "pen UP survives target publication");
        equal("release", port.calls.get(port.calls.size() - 1),
            "late terminal drains the deliberately dropped contact");
        status(session.activation(), ActivationMachine.State.ACTIVE, 0, true);
    }

    private static void testControllerSynchronousCallbacks() {
        SpreadSession session = initializedSession(1, 21, 1);
        SynchronousPort port = new SynchronousPort(session, 21);
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        port.controller = controller;
        NativeReaderController.DownDecision down = controller.onDown(
            0, 1200, 500, 0.5, 0,
            GestureRouter.Tool.STYLUS, Collections.<RectD>emptyList()
        );
        equal(NativeReaderController.InputResult.CONSUMED, down.result,
            "synchronous callback pen begins");
        equal(ActivationMachine.State.DRAINING_CONTACT,
            session.activation().status().state,
            "synchronous target callback still waits for UP");
        controller.onMotion(
            down.gestureTokenId, 0, GestureAction.UP,
            1210, 510, 0, 10
        );
        equal(Arrays.asList(
            "freeze", "save", "disableWriter", "load",
            "release"
        ), port.calls, "fully synchronous port completes without deadlock");
        status(session.activation(), ActivationMachine.State.ACTIVE, 0, true);
    }

    private static void testControllerCallbackOrdering() {
        SpreadSession duplicateSession = initializedSession(1, 22, 1);
        FakePort duplicatePort = new FakePort();
        NativeReaderController duplicateController =
            new NativeReaderController(
                duplicateSession, duplicatePort
            );
        duplicateController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        ActivationMachine.Token duplicateToken = duplicatePort.lastToken;
        duplicateController.onSourceSaveComplete(duplicateToken, true);
        int callsAfterSave = duplicatePort.calls.size();
        duplicateController.onSourceSaveComplete(duplicateToken, true);
        equal(callsAfterSave, duplicatePort.calls.size(),
            "duplicate source-save callback is idempotent");
        duplicateController.onTargetLoadComplete(duplicateToken, 0, true);
        int callsAfterLoad = duplicatePort.calls.size();
        duplicateController.onTargetLoadComplete(duplicateToken, 0, false);
        equal(callsAfterLoad, duplicatePort.calls.size(),
            "duplicate target-load callback is idempotent");
        duplicateController.onTargetReady(
            duplicateToken,
            authority(0, 22, 2),
            spread(0, 22, 2, true)
        );
        int callsAfterReady = duplicatePort.calls.size();
        duplicateController.onTargetReady(
            duplicateToken,
            authority(0, 22, 3),
            spread(0, 22, 3, true)
        );
        equal(callsAfterReady, duplicatePort.calls.size(),
            "duplicate target-ready callback cannot republish");

        SpreadSession reorderedSession = initializedSession(1, 23, 1);
        FakePort reorderedPort = new FakePort();
        NativeReaderController reorderedController =
            new NativeReaderController(
                reorderedSession, reorderedPort
            );
        reorderedController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        ActivationMachine.Token reorderedToken = reorderedPort.lastToken;
        reorderedController.onTargetLoadComplete(reorderedToken, 0, true);
        equal("rollback", reorderedPort.calls.get(
            reorderedPort.calls.size() - 1
        ), "out-of-order target load rolls back");
        int rollbackCalls = reorderedPort.calls.size();
        reorderedController.onSourceSaveComplete(reorderedToken, false);
        equal(rollbackCalls, reorderedPort.calls.size(),
            "late source callback cannot request a second rollback");
        reorderedController.onRollbackReady(
            reorderedToken,
            authority(1, 23, 2),
            spread(1, 23, 2, true)
        );
        reorderedController.onRollbackFailed(
            reorderedToken, "stale_failure_after_success"
        );
        check(reorderedSession.snapshot() != null,
            "stale rollback failure cannot disable recovered session");

        SpreadSession busySession = initializedSession(1, 24, 1);
        FakePort busyPort = new FakePort();
        NativeReaderController busyController = new NativeReaderController(
            busySession, busyPort
        );
        check(busyController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        ), "hover transaction begins for busy gate");
        equal(NativeReaderController.InputResult.BLOCKED,
            busyController.onDown(
                0, 100, 500, 0.5, 0,
                GestureRouter.Tool.STYLUS,
                Collections.<RectD>emptyList()
            ).result,
            "new source-page contact cannot bypass pending activation");
        busyController.onActivationTimeout(busyPort.lastToken);
        equal("rollback", busyPort.calls.get(busyPort.calls.size() - 1),
            "activation timeout requests rollback");
        int timeoutCalls = busyPort.calls.size();
        busyController.onActivationTimeout(busyPort.lastToken);
        equal(timeoutCalls, busyPort.calls.size(),
            "duplicate timeout cannot request duplicate rollback");

        SpreadSession contactSession = initializedSession(1, 25, 1);
        FakePort contactPort = new FakePort();
        NativeReaderController contactController =
            new NativeReaderController(
                contactSession, contactPort
            );
        NativeReaderController.DownDecision activeContact =
            contactController.onDown(
                0, 100, 500, 0.5, 0,
                GestureRouter.Tool.STYLUS,
                Collections.<RectD>emptyList()
            );
        check(!contactController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        ), "hover cannot activate during a native contact");
        equal(0, contactPort.calls.size(),
            "rejected hover does not reach firmware");
        contactController.onMotion(
            activeContact.gestureTokenId,
            0,
            GestureAction.UP,
            100,
            500,
            0,
            10
        );
    }

    private static void testControllerPortFailures() {
        assertPortFailureRollsBack(FailurePoint.FREEZE, 30);
        assertPortFailureRollsBack(FailurePoint.SAVE, 31);
        assertPortFailureRollsBack(FailurePoint.DISABLE_WRITER, 32);
        assertPortFailureRollsBack(FailurePoint.LOAD, 33);

        SpreadSession replaySession = initializedSession(1, 34, 1);
        ThrowingPort replayPort = new ThrowingPort(FailurePoint.REPLAY);
        NativeReaderController replayController = new NativeReaderController(
            replaySession, replayPort
        );
        NativeReaderController.DownDecision replay = replayController.onDown(
            0, 1200, 500, 0.0, 0,
            GestureRouter.Tool.FINGER, Collections.<RectD>emptyList()
        );
        replayController.onMotion(
            replay.gestureTokenId, 0, GestureAction.UP,
            1210, 510, 0, 10
        );
        ActivationMachine.Token replayToken = replayPort.lastToken;
        replayController.onSourceSaveComplete(replayToken, true);
        replayController.onTargetLoadComplete(replayToken, 0, true);
        replayController.onTargetReady(
            replayToken,
            authority(0, 34, 2),
            spread(0, 34, 2, true)
        );
        check(replaySession.snapshot() == null,
            "replay request exception hard-disables authority");

        SpreadSession rollbackSession = initializedSession(1, 35, 1);
        ThrowingPort rollbackPort = new ThrowingPort(FailurePoint.ROLLBACK);
        NativeReaderController rollbackController =
            new NativeReaderController(
                rollbackSession, rollbackPort
            );
        rollbackController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        rollbackController.onSourceSaveComplete(rollbackPort.lastToken, false);
        check(rollbackSession.snapshot() == null,
            "rollback request exception hard-disables authority");

        SpreadSession releaseSession = initializedSession(1, 36, 1);
        ThrowingPort releasePort = new ThrowingPort(FailurePoint.RELEASE);
        NativeReaderController releaseController =
            new NativeReaderController(
                releaseSession, releasePort
            );
        releaseController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        ActivationMachine.Token releaseToken = releasePort.lastToken;
        releaseController.onSourceSaveComplete(releaseToken, true);
        releaseController.onTargetLoadComplete(releaseToken, 0, true);
        releaseController.onTargetReady(
            releaseToken,
            authority(0, 36, 2),
            spread(0, 36, 2, true)
        );
        check(releaseSession.snapshot() == null,
            "release exception hard-disables authority");
    }

    private static void assertPortFailureRollsBack(
        FailurePoint failure,
        long activityGeneration
    ) {
        SpreadSession session = initializedSession(
            1, activityGeneration, 1
        );
        ThrowingPort port = new ThrowingPort(failure);
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        if (failure == FailurePoint.FREEZE || failure == FailurePoint.SAVE) {
            controller.onInactiveHover(
                1200, 500, Collections.<RectD>emptyList()
            );
        } else {
            controller.onInactiveHover(
                1200, 500, Collections.<RectD>emptyList()
            );
            controller.onSourceSaveComplete(port.lastToken, true);
        }
        equal("rollback", port.calls.get(port.calls.size() - 1),
            failure + " exception requests rollback");
        check(session.snapshot() != null,
            failure + " exception does not publish uncertain target");
    }

    private static void testControllerInvalidInput() {
        SpreadSession session = initializedSession(1, 40, 1);
        FakePort port = new FakePort();
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        equal(NativeReaderController.InputResult.BLOCKED,
            controller.onDown(
                0, Double.NaN, 500, 0.5, 0,
                GestureRouter.Tool.STYLUS,
                Collections.<RectD>emptyList()
            ).result, "non-finite DOWN rejected before transaction");
        equal(NativeReaderController.InputResult.BLOCKED,
            controller.onDown(
                0, 1200, 500, -0.1, 0,
                GestureRouter.Tool.STYLUS,
                Collections.<RectD>emptyList()
            ).result, "negative pressure DOWN rejected");
        equal(NativeReaderController.InputResult.BLOCKED,
            controller.onDown(
                0, 1200, 500, 0.5, -1,
                GestureRouter.Tool.STYLUS,
                Collections.<RectD>emptyList()
            ).result, "negative event time DOWN rejected");
        equal(0, port.calls.size(),
            "invalid DOWN cannot reach firmware port");

        NativeReaderController.DownDecision valid = controller.onDown(
            0, 1200, 500, 0.5, 0,
            GestureRouter.Tool.STYLUS, Collections.<RectD>emptyList()
        );
        equal(NativeReaderController.InputResult.BLOCKED,
            controller.onMotion(
                valid.gestureTokenId, 0, GestureAction.MOVE,
                1210, Double.POSITIVE_INFINITY, 0.5, 1
            ), "invalid buffered MOVE is blocked");
        equal("rollback", port.calls.get(port.calls.size() - 1),
            "invalid buffered MOVE requests rollback");

        SpreadSession fingerSession = initializedSession(1, 401, 1);
        FakePort fingerPort = new FakePort();
        NativeReaderController fingerController =
            new NativeReaderController(fingerSession, fingerPort);
        NativeReaderController.DownDecision finger = fingerController.onDown(
            3, 1200, 500, 0.0, 10,
            GestureRouter.Tool.FINGER, Collections.<RectD>emptyList()
        );
        equal(NativeReaderController.InputResult.CONSUMED, finger.result,
            "inactive finger begins deferred activation");
        equal(NativeReaderController.InputResult.BLOCKED,
            fingerController.onMotion(
                finger.gestureTokenId, 3, GestureAction.MOVE,
                Double.NaN, 510, 0.0, 11
            ), "invalid deferred finger MOVE is blocked");
        equal(0, fingerPort.calls.size(),
            "invalid deferred finger cannot reach firmware");
        NativeReaderController.DownDecision recovered =
            fingerController.onDown(
                4, 1200, 500, 0.0, 12,
                GestureRouter.Tool.FINGER,
                Collections.<RectD>emptyList()
            );
        equal(NativeReaderController.InputResult.CONSUMED, recovered.result,
            "invalid deferred finger releases controller context");
        fingerController.onMotion(
            recovered.gestureTokenId, 4, GestureAction.CANCEL,
            1200, 500, 0.0, 13
        );
    }

    private static void testControllerRetirementAndReplayTimeout() {
        SpreadSession retiredSession = initializedSession(1, 41, 1);
        FakePort retiredPort = new FakePort();
        NativeReaderController retiredController =
            new NativeReaderController(
                retiredSession, retiredPort
            );
        retiredController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        ActivationMachine.Token retiredToken = retiredPort.lastToken;
        int callsBeforeRetire = retiredPort.calls.size();
        retiredController.retire();
        retiredController.onSourceSaveComplete(retiredToken, true);
        retiredController.onTargetLoadComplete(retiredToken, 0, true);
        retiredController.onTargetReady(
            retiredToken,
            authority(0, 41, 2),
            spread(0, 41, 2, true)
        );
        equal(callsBeforeRetire, retiredPort.calls.size(),
            "retired callbacks cannot reach firmware port");
        check(retiredSession.snapshot() == null,
            "retirement clears published authority");
        equal(NativeReaderController.InputResult.BLOCKED,
            retiredController.onDown(
                0, 100, 500, 0.5, 0,
                GestureRouter.Tool.STYLUS,
                Collections.<RectD>emptyList()
            ).result, "retired controller rejects new input");

        SpreadSession timeoutSession = initializedSession(1, 42, 1);
        FakePort timeoutPort = new FakePort();
        NativeReaderController timeoutController =
            new NativeReaderController(
                timeoutSession, timeoutPort
        );
        NativeReaderController.DownDecision down = timeoutController.onDown(
            0, 1200, 500, 0.0, 0,
            GestureRouter.Tool.FINGER, Collections.<RectD>emptyList()
        );
        timeoutController.onMotion(
            down.gestureTokenId, 0, GestureAction.UP,
            1210, 510, 0, 10
        );
        ActivationMachine.Token timeoutToken = timeoutPort.lastToken;
        timeoutController.onSourceSaveComplete(timeoutToken, true);
        timeoutController.onTargetLoadComplete(timeoutToken, 0, true);
        timeoutController.onTargetReady(
            timeoutToken,
            authority(0, 42, 2),
            spread(0, 42, 2, true)
        );
        equal("replayFinger", timeoutPort.calls.get(
            timeoutPort.calls.size() - 1
        ), "replay dispatched before timeout fixture");
        timeoutController.onActivationTimeout(timeoutToken);
        equal("disable", timeoutPort.calls.get(
            timeoutPort.calls.size() - 1
        ), "replay timeout hard-disables instead of unsafe rollback");
        check(timeoutSession.snapshot() == null,
            "uncertain replay timeout retires authority");
    }

    private static void testControllerThreadConfinement() throws Exception {
        SpreadSession session = initializedSession(1, 43, 1);
        FakePort port = new FakePort();
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        AtomicInteger rejected = new AtomicInteger();
        Thread wrongThread = new Thread(() -> {
            try {
                controller.onInactiveHover(
                    1200, 500, Collections.<RectD>emptyList()
                );
            } catch (IllegalStateException expected) {
                rejected.incrementAndGet();
            }
        });
        wrongThread.start();
        wrongThread.join();
        equal(1, rejected.get(),
            "off-owner callback is rejected deterministically");
        equal(0, port.calls.size(),
            "off-owner callback cannot reach firmware port");
        equal(1, session.snapshot().activePageIndex,
            "off-owner callback cannot change page authority");
    }

    private static void testFirmwarePortActivationAndReplay() {
        SpreadSession hoverSession = initializedSession(1, 50, 1);
        FirmwareBridge hoverBridge = new FirmwareBridge(1, 50, 1);
        NativeReaderFirmwarePort hoverPort =
            firmwarePort(hoverBridge);
        NativeReaderController hoverController = new NativeReaderController(
            hoverSession, hoverPort
        );
        hoverPort.attachController(hoverController);
        check(hoverController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        ), "firmware hover activation begins");
        equal(NativeReaderFirmwarePort.Phase.TARGET_LOADING,
            hoverPort.phase(), "firmware waits for complete target readiness");
        equal(Arrays.asList("freeze", "save", "disable", "load:0"),
            hoverBridge.calls, "firmware source transfer order");
        equal(1, hoverBridge.activationTimeouts.size(),
            "firmware schedules one watchdog per activation");
        hoverBridge.ready(0, 2);
        hoverPort.onFirmwarePageReady(hoverBridge.observe());
        equal(NativeReaderFirmwarePort.Phase.IDLE, hoverPort.phase(),
            "hover activation releases input");
        equal(0, hoverSession.snapshot().activePageIndex,
            "hover publishes target page");
        equal("release", hoverBridge.calls.get(hoverBridge.calls.size() - 1),
            "hover releases only after target publication");
        int callsAfterSuccessfulActivation = hoverBridge.calls.size();
        hoverBridge.fireActivationTimeout(0);
        equal(callsAfterSuccessfulActivation, hoverBridge.calls.size(),
            "expired watchdog cannot disturb completed activation");

        SpreadSession penSession = initializedSession(1, 51, 1);
        FirmwareBridge penBridge = new FirmwareBridge(1, 51, 1);
        NativeReaderFirmwarePort penPort =
            firmwarePort(penBridge);
        NativeReaderController penController = new NativeReaderController(
            penSession, penPort
        );
        penPort.attachController(penController);
        NativeReaderController.DownDecision down = penController.onDown(
            4, 1200, 500, 0.7, 10,
            GestureRouter.Tool.STYLUS,
            Collections.<RectD>emptyList()
        );
        penController.onMotion(
            down.gestureTokenId,
            4,
            GestureAction.UP,
            1220,
            520,
            0.0,
            20
        );
        penBridge.ready(0, 2);
        penPort.onFirmwarePageReady(penBridge.observe());
        equal(NativeReaderFirmwarePort.Phase.IDLE, penPort.phase(),
            "dropped direct pen contact completes transaction");
        check(!penBridge.calls.contains("replayFinger"),
            "direct pen contact is not synthetically replayed");
        equal("release", penBridge.calls.get(penBridge.calls.size() - 1),
            "pen releases after physical contact drains");
        equal(0, penSession.snapshot().activePageIndex,
            "pen target remains authoritative");
    }

    private static void testFirmwarePortDeferredSaveCallbacks()
        throws Exception {
        SpreadSession delayedSession = initializedSession(1, 57, 1);
        FirmwareBridge delayedBridge = new FirmwareBridge(1, 57, 1);
        delayedBridge.deferSave = true;
        NativeReaderFirmwarePort delayedPort = firmwarePort(delayedBridge);
        NativeReaderController delayedController = new NativeReaderController(
            delayedSession, delayedPort
        );
        delayedPort.attachController(delayedController);
        check(delayedController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        ), "deferred firmware save begins");
        equal(NativeReaderFirmwarePort.Phase.FROZEN, delayedPort.phase(),
            "pen-down path returns before native save completion");
        equal(Arrays.asList("freeze", "save"), delayedBridge.calls,
            "deferred save performs no writer or page mutation early");
        delayedBridge.completeSave(true);
        equal(NativeReaderFirmwarePort.Phase.TARGET_LOADING,
            delayedPort.phase(), "owner save completion advances transfer");
        int callsAfterFirstCompletion = delayedBridge.calls.size();
        delayedBridge.repeatLastSaveCompletion(true);
        equal(callsAfterFirstCompletion, delayedBridge.calls.size(),
            "duplicate save completion is idempotent");

        SpreadSession timeoutSession = initializedSession(1, 60, 1);
        FirmwareBridge timeoutBridge = new FirmwareBridge(1, 60, 1);
        timeoutBridge.deferSave = true;
        NativeReaderFirmwarePort timeoutPort = firmwarePort(timeoutBridge);
        NativeReaderController timeoutController =
            new NativeReaderController(timeoutSession, timeoutPort);
        timeoutPort.attachController(timeoutController);
        check(timeoutController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        ), "watchdog activation begins");
        equal(NativeReaderFirmwarePort.Phase.FROZEN, timeoutPort.phase(),
            "watchdog observes deferred source save");
        equal(1, timeoutBridge.activationTimeouts.size(),
            "watchdog is armed before deferred save can hang");
        timeoutBridge.fireActivationTimeout(0);
        equal(NativeReaderFirmwarePort.Phase.ROLLBACK_LOADING,
            timeoutPort.phase(), "watchdog requests source rollback");
        equal("load:1",
            timeoutBridge.calls.get(timeoutBridge.calls.size() - 1),
            "watchdog rollback reloads authoritative source page");
        int callsAfterTimeout = timeoutBridge.calls.size();
        timeoutBridge.completeSave(true);
        equal(callsAfterTimeout, timeoutBridge.calls.size(),
            "late save after watchdog cannot restart target transfer");

        SpreadSession threadedSession = initializedSession(1, 58, 1);
        FirmwareBridge threadedBridge = new FirmwareBridge(1, 58, 1);
        threadedBridge.deferSave = true;
        NativeReaderFirmwarePort threadedPort = firmwarePort(threadedBridge);
        NativeReaderController threadedController = new NativeReaderController(
            threadedSession, threadedPort
        );
        threadedPort.attachController(threadedController);
        threadedController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        Thread callbackThread = new Thread(
            () -> threadedBridge.completeSave(true)
        );
        callbackThread.start();
        callbackThread.join();
        equal(NativeReaderFirmwarePort.Phase.FROZEN, threadedPort.phase(),
            "background save completion cannot enter owner state directly");
        threadedBridge.drainOwnerCallbacks();
        equal(NativeReaderFirmwarePort.Phase.TARGET_LOADING,
            threadedPort.phase(), "background completion is owner-marshalled");

        SpreadSession staleSession = initializedSession(1, 59, 1);
        FirmwareBridge staleBridge = new FirmwareBridge(1, 59, 1);
        staleBridge.deferSave = true;
        NativeReaderFirmwarePort stalePort = firmwarePort(staleBridge);
        NativeReaderController staleController = new NativeReaderController(
            staleSession, stalePort
        );
        stalePort.attachController(staleController);
        staleController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        staleBridge.completeSave(false);
        equal(NativeReaderFirmwarePort.Phase.ROLLBACK_LOADING,
            stalePort.phase(), "failed save begins rollback");
        int callsBeforeLateCompletion = staleBridge.calls.size();
        staleBridge.repeatLastSaveCompletion(true);
        equal(callsBeforeLateCompletion, staleBridge.calls.size(),
            "late save completion cannot restart target transfer");
    }

    private static void testFirmwarePortRollbackAndFailClosed() {
        SpreadSession saveSession = initializedSession(1, 55, 1);
        FirmwareBridge saveBridge = new FirmwareBridge(1, 55, 1);
        saveBridge.markRevision = 5;
        saveBridge.saveRevisionDelta = -1;
        NativeReaderFirmwarePort savePort =
            firmwarePort(saveBridge);
        NativeReaderController saveController = new NativeReaderController(
            saveSession, savePort
        );
        savePort.attachController(saveController);
        saveController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        equal(NativeReaderFirmwarePort.Phase.ROLLBACK_LOADING,
            savePort.phase(), "regressed mark revision triggers rollback");
        check(!saveBridge.calls.contains("load:0"),
            "regressed save revision cannot load target");

        SpreadSession disableSession = initializedSession(1, 56, 1);
        FirmwareBridge disableBridge = new FirmwareBridge(1, 56, 1);
        disableBridge.refuseDisable = true;
        NativeReaderFirmwarePort disablePort =
            firmwarePort(disableBridge);
        NativeReaderController disableController = new NativeReaderController(
            disableSession, disablePort
        );
        disablePort.attachController(disableController);
        disableController.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        equal(NativeReaderFirmwarePort.Phase.ROLLBACK_LOADING,
            disablePort.phase(), "writer-disable failure triggers rollback");
        check(!disableBridge.calls.contains("load:0"),
            "enabled source writer cannot load target");

        SpreadSession session = initializedSession(1, 52, 1);
        FirmwareBridge bridge = new FirmwareBridge(1, 52, 1);
        NativeReaderFirmwarePort port = firmwarePort(bridge);
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        port.attachController(controller);
        controller.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        );
        bridge.ready(0, 1); // target page with a stale layout generation
        port.onFirmwarePageReady(bridge.observe());
        equal(NativeReaderFirmwarePort.Phase.ROLLBACK_LOADING, port.phase(),
            "stale target authority requests source rollback");
        equal("load:1", bridge.calls.get(bridge.calls.size() - 1),
            "rollback reloads exact source page");
        bridge.ready(1, 2);
        port.onFirmwarePageReady(bridge.observe());
        equal(NativeReaderFirmwarePort.Phase.IDLE, port.phase(),
            "verified source rollback releases input");
        equal(1, session.snapshot().activePageIndex,
            "rollback preserves source authority");

        SpreadSession replaySession = initializedSession(1, 53, 1);
        FirmwareBridge replayBridge = new FirmwareBridge(1, 53, 1);
        NativeReaderFirmwarePort replayPort =
            firmwarePort(replayBridge);
        NativeReaderController replayController = new NativeReaderController(
            replaySession, replayPort
        );
        replayPort.attachController(replayController);
        NativeReaderController.DownDecision down = replayController.onDown(
            1, 1200, 500, 0.0, 0,
            GestureRouter.Tool.FINGER,
            Collections.<RectD>emptyList()
        );
        replayController.onMotion(
            down.gestureTokenId, 1, GestureAction.UP,
            1210, 510, 0.0, 10
        );
        replayBridge.ready(0, 2);
        replayBridge.replaceComponentsAfterReplay = true;
        replayPort.onFirmwarePageReady(replayBridge.observe());
        equal(NativeReaderFirmwarePort.Phase.DISABLED, replayPort.phase(),
            "uncertain post-replay authority hard-disables feature");
        check(replaySession.snapshot() == null,
            "uncertain replay retires published session");
        equal("disableFeature:native_replay_failed_or_uncertain",
            replayBridge.calls.get(replayBridge.calls.size() - 1),
            "uncertain replay cannot attempt an unsafe rollback");
    }

    private static void testFirmwarePortAuthorityAndThreadConfinement()
        throws Exception {
        SpreadSession session = initializedSession(1, 54, 1);
        FirmwareBridge bridge = new FirmwareBridge(1, 54, 1);
        NativeReaderFirmwarePort port = firmwarePort(bridge);
        NativeReaderController controller = new NativeReaderController(
            session, port
        );
        port.attachController(controller);
        expectThrows(() -> port.attachController(controller),
            "firmware controller attaches once");
        AtomicInteger rejected = new AtomicInteger();
        Thread wrongThread = new Thread(() -> {
            try {
                port.phase();
            } catch (IllegalStateException expected) {
                rejected.incrementAndGet();
            }
        });
        wrongThread.start();
        wrongThread.join();
        equal(1, rejected.get(),
            "off-owner firmware callback is rejected");

        bridge.activityGeneration = 999;
        check(controller.onInactiveHover(
            1200, 500, Collections.<RectD>emptyList()
        ), "mismatched authority reaches fail-closed activation boundary");
        equal(NativeReaderFirmwarePort.Phase.DISABLED, port.phase(),
            "authority rejection hard-disables incomplete adapter state");
        check(!bridge.calls.contains("freeze"),
            "authority rejection precedes native mutation");
    }

    private static void testFirmwareSymbolContractDigest() {
        equal(
            com.techrebbe.supernote.spreadprobe.v2.android
                .NativeReaderFirmwareAdmission.EXPECTED_SYMBOL_DIGEST,
            com.techrebbe.supernote.spreadprobe.v2.android
                .NativeReaderFirmwareAdmission.compiledSymbolDigest(),
            "firmware symbol contract digest is frozen"
        );
    }

    private static NativeReaderFirmwarePort firmwarePort(
        FirmwareBridge bridge
    ) {
        return new NativeReaderFirmwarePort(bridge, bridge.observe());
    }

    private static SpreadSession initializedSession(
        int active,
        long activityGeneration,
        long layoutGeneration
    ) {
        SpreadSession session = new SpreadSession();
        check(session.publish(spread(
            active,
            activityGeneration,
            layoutGeneration,
            true
        )), "controller fixture publishes");
        return session;
    }

    private static SpreadSnapshot spread(
        int active,
        long activityGeneration,
        long layoutGeneration,
        boolean writerReady
    ) {
        return new SpreadSnapshot(
            "doc",
            activityGeneration,
            layoutGeneration,
            10,
            active,
            SpreadSnapshot.Mode.SPREAD,
            leftSlot(1),
            rightSlot(0),
            writerReady
                ? authority(active, activityGeneration, layoutGeneration)
                : null,
            writerReady
        );
    }

    private static PageSlot leftSlot(int page) {
        return new PageSlot(
            page,
            PageSlot.Side.LEFT,
            new RectD(0, 0, 1000, 1400),
            new RectD(0, 0, 936, 1404),
            new Affine2D(0.936, 0, 0, 0.936, 0, 46.8)
        );
    }

    private static PageSlot rightSlot(int page) {
        return new PageSlot(
            page,
            PageSlot.Side.RIGHT,
            new RectD(0, 0, 1000, 1400),
            new RectD(936, 0, 1872, 1404),
            new Affine2D(0.936, 0, 0, 0.936, 936, 46.8)
        );
    }

    private static NativeAuthority authority(
        int page,
        long activityGeneration,
        long layoutGeneration
    ) {
        return new NativeAuthority(
            "doc",
            activityGeneration,
            layoutGeneration,
            page,
            11,
            12,
            13,
            14,
            page
        );
    }

    private static void status(
        ActivationMachine machine,
        ActivationMachine.State state,
        int page,
        boolean writer
    ) {
        ActivationMachine.Status status = machine.status();
        equal(state, status.state, "activation state");
        equal(page, status.activePage, "activation page");
        equal(writer, status.writerEnabled, "writer state");
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void equal(Object expected, Object actual, String message) {
        check(expected == null ? actual == null : expected.equals(actual),
            message + ": expected=" + expected + " actual=" + actual);
    }

    private static void near(
        double expected,
        double actual,
        double tolerance,
        String message
    ) {
        check(Math.abs(expected - actual) <= tolerance,
            message + ": expected=" + expected + " actual=" + actual);
    }

    private static void expectThrows(Runnable action, String message) {
        assertions++;
        try {
            action.run();
        } catch (RuntimeException expected) {
            return;
        }
        throw new AssertionError(message + ": expected exception");
    }

    private enum FailurePoint {
        NONE,
        FREEZE,
        SAVE,
        DISABLE_WRITER,
        LOAD,
        REPLAY,
        ROLLBACK,
        RELEASE
    }

    private static final class FirmwareBridge
        implements NativeReaderFirmwarePort.Bridge {
        final List<String> calls = new ArrayList<>();
        int activePage;
        long activityGeneration;
        long layoutGeneration;
        long markRevision;
        long saveRevisionDelta = 1L;
        boolean writerEnabled = true;
        boolean refuseDisable;
        boolean replaceComponentsAfterReplay;
        boolean deferSave;
        long componentSalt;
        final long ownerThreadId = Thread.currentThread().getId();
        final List<Runnable> ownerCallbacks = new ArrayList<>();
        final List<Runnable> activationTimeouts = new ArrayList<>();
        NativeReaderFirmwarePort.Bridge.SourceSaveCallback pendingSave;
        NativeReaderFirmwarePort.Bridge.SourceSaveCallback lastSave;

        FirmwareBridge(
            int activePage,
            long activityGeneration,
            long layoutGeneration
        ) {
            this.activePage = activePage;
            this.activityGeneration = activityGeneration;
            this.layoutGeneration = layoutGeneration;
        }

        void ready(int page, long layout) {
            activePage = page;
            layoutGeneration = layout;
            writerEnabled = true;
        }

        void completeSave(boolean saved) {
            NativeReaderFirmwarePort.Bridge.SourceSaveCallback callback =
                pendingSave;
            if (callback == null) {
                throw new IllegalStateException("no deferred save callback");
            }
            pendingSave = null;
            lastSave = callback;
            if (saved) {
                markRevision += saveRevisionDelta;
            }
            callback.onComplete(saved, observe());
        }

        void repeatLastSaveCompletion(boolean saved) {
            if (lastSave == null) {
                throw new IllegalStateException("no completed save callback");
            }
            lastSave.onComplete(saved, observe());
        }

        void drainOwnerCallbacks() {
            if (Thread.currentThread().getId() != ownerThreadId) {
                throw new IllegalStateException("not the bridge owner thread");
            }
            while (true) {
                Runnable callback;
                synchronized (ownerCallbacks) {
                    if (ownerCallbacks.isEmpty()) {
                        return;
                    }
                    callback = ownerCallbacks.remove(0);
                }
                callback.run();
            }
        }

        void fireActivationTimeout(int index) {
            if (index < 0 || index >= activationTimeouts.size()) {
                throw new IllegalStateException("no activation timeout");
            }
            activationTimeouts.get(index).run();
        }

        @Override
        public NativeReaderFirmwarePort.Observation observe() {
            long observedActivity = activityGeneration;
            NativeAuthority observedAuthority = writerEnabled
                ? new NativeAuthority(
                    "doc",
                    observedActivity,
                    layoutGeneration,
                    activePage,
                    11 + componentSalt,
                    12 + componentSalt,
                    13 + componentSalt,
                    14 + componentSalt,
                    activePage
                ) : null;
            SpreadSnapshot observed = new SpreadSnapshot(
                "doc",
                observedActivity,
                layoutGeneration,
                10,
                activePage,
                SpreadSnapshot.Mode.SPREAD,
                leftSlot(1),
                rightSlot(0),
                observedAuthority,
                writerEnabled
            );
            return new NativeReaderFirmwarePort.Observation(
                observedAuthority,
                observed,
                writerEnabled,
                markRevision
            );
        }

        @Override
        public boolean isStableObservationCurrent(
            NativeReaderFirmwarePort.Observation expected
        ) {
            if (expected == null) {
                return false;
            }
            NativeReaderFirmwarePort.Observation current = observe();
            return current.snapshot.documentId.equals(
                expected.snapshot.documentId
            ) && current.snapshot.activityGeneration
                == expected.snapshot.activityGeneration
                && current.snapshot.layoutGeneration
                    == expected.snapshot.layoutGeneration
                && current.snapshot.activePageIndex
                    == expected.snapshot.activePageIndex
                && current.writerEnabled == expected.writerEnabled
                && (current.authority == null
                    ? expected.authority == null
                    : current.authority.equals(expected.authority));
        }

        @Override
        public void freezeDocumentInput() {
            calls.add("freeze");
        }

        @Override
        public void requestNativeSourceSave(
            NativeReaderFirmwarePort.Bridge.SourceSaveCallback callback
        ) {
            calls.add("save");
            if (pendingSave != null) {
                throw new IllegalStateException("overlapping native save");
            }
            pendingSave = callback;
            if (!deferSave) {
                completeSave(true);
            }
        }

        @Override
        public void postToOwnerThread(Runnable callback) {
            if (Thread.currentThread().getId() == ownerThreadId) {
                callback.run();
                return;
            }
            synchronized (ownerCallbacks) {
                ownerCallbacks.add(callback);
            }
        }

        @Override
        public void scheduleActivationTimeout(Runnable callback) {
            activationTimeouts.add(callback);
        }

        @Override
        public void disableNativeWriter() {
            calls.add("disable");
            if (!refuseDisable) {
                writerEnabled = false;
            }
        }

        @Override
        public void loadNativePage(int page) {
            calls.add("load:" + page);
        }

        @Override
        public void replayNativeFingerHit(PointD sourcePoint) {
            calls.add("replayFinger");
            if (replaceComponentsAfterReplay) {
                componentSalt++;
            }
        }

        @Override
        public int nativeSpreadNavigationTarget(
            SpreadSnapshot sourceSnapshot,
            double deltaX,
            double deltaY
        ) {
            calls.add("navigateTarget");
            return 2;
        }

        @Override
        public void releaseDocumentInput() {
            calls.add("release");
        }

        @Override
        public void disableNativeReaderV2(String reason) {
            calls.add("disableFeature:" + reason);
            writerEnabled = false;
        }
    }

    private static class FakePort
        implements NativeReaderController.Port {
        final List<String> calls = new ArrayList<>();
        ActivationMachine.Token lastToken;
        PointD replayedFinger;

        @Override
        public void freezeInput(ActivationMachine.Token token) {
            lastToken = token;
            calls.add("freeze");
        }

        @Override
        public void requestSourceSave(ActivationMachine.Token token) {
            lastToken = token;
            calls.add("save");
        }

        @Override
        public void disableWriter(ActivationMachine.Token token) {
            calls.add("disableWriter");
        }

        @Override
        public void requestTargetLoad(ActivationMachine.Token token) {
            calls.add("load");
        }

        @Override
        public void replayFingerHit(
            ActivationMachine.Token token,
            PointD sourcePoint
        ) {
            replayedFinger = sourcePoint;
            calls.add("replayFinger");
        }

        @Override
        public int navigationTarget(
            SpreadSnapshot sourceSnapshot,
            double deltaX,
            double deltaY
        ) {
            calls.add("navigateTarget");
            return 0;
        }

        @Override
        public void releaseInput(ActivationMachine.Token token) {
            calls.add("release");
        }

        @Override
        public void requestRollback(ActivationMachine.Token token) {
            calls.add("rollback");
        }

        @Override
        public void disableFeature(
            ActivationMachine.Token token,
            String reason
        ) {
            calls.add("disable");
        }
    }

    private static final class SynchronousPort extends FakePort {
        final SpreadSession session;
        final long activityGeneration;
        NativeReaderController controller;

        SynchronousPort(
            SpreadSession session,
            long activityGeneration
        ) {
            this.session = session;
            this.activityGeneration = activityGeneration;
        }

        @Override
        public void requestSourceSave(ActivationMachine.Token token) {
            super.requestSourceSave(token);
            controller.onSourceSaveComplete(token, true);
        }

        @Override
        public void requestTargetLoad(ActivationMachine.Token token) {
            super.requestTargetLoad(token);
            controller.onTargetLoadComplete(token, token.targetPage, true);
            controller.onTargetReady(
                token,
                authority(token.targetPage, activityGeneration, 2),
                spread(token.targetPage, activityGeneration, 2, true)
            );
        }

        @Override
        public void replayFingerHit(
            ActivationMachine.Token token,
            PointD sourcePoint
        ) {
            super.replayFingerHit(token, sourcePoint);
            controller.onReplayComplete(token, true);
        }
    }

    private static final class ThrowingPort extends FakePort {
        final FailurePoint failure;

        ThrowingPort(FailurePoint failure) {
            this.failure = failure;
        }

        @Override
        public void freezeInput(ActivationMachine.Token token) {
            super.freezeInput(token);
            throwIf(FailurePoint.FREEZE);
        }

        @Override
        public void requestSourceSave(ActivationMachine.Token token) {
            super.requestSourceSave(token);
            throwIf(FailurePoint.SAVE);
        }

        @Override
        public void disableWriter(ActivationMachine.Token token) {
            super.disableWriter(token);
            throwIf(FailurePoint.DISABLE_WRITER);
        }

        @Override
        public void requestTargetLoad(ActivationMachine.Token token) {
            super.requestTargetLoad(token);
            throwIf(FailurePoint.LOAD);
        }

        @Override
        public void replayFingerHit(
            ActivationMachine.Token token,
            PointD sourcePoint
        ) {
            super.replayFingerHit(token, sourcePoint);
            throwIf(FailurePoint.REPLAY);
        }

        @Override
        public void requestRollback(ActivationMachine.Token token) {
            super.requestRollback(token);
            throwIf(FailurePoint.ROLLBACK);
        }

        @Override
        public void releaseInput(ActivationMachine.Token token) {
            super.releaseInput(token);
            throwIf(FailurePoint.RELEASE);
        }

        private void throwIf(FailurePoint point) {
            if (failure == point) {
                throw new IllegalStateException("injected " + point);
            }
        }
    }
}
