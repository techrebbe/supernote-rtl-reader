package com.techrebbe.supernote.spreadprobe.v2android;

import android.os.Build;

import com.techrebbe.supernote.spreadprobe.v2.android.NativeReaderFirmwareAdmission;

import java.io.File;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Exclusive LSPosed entry point for Native Reader v2.
 *
 * The preserved experimental SpreadProbe class is deliberately not loaded.
 * No v2 hook is installed unless both the system APK and every reflected
 * firmware symbol match the one inspected Supernote build exactly.
 */
public final class NativeReaderV2EntryPoint
    implements IXposedHookLoadPackage {
    private static final String TARGET_PACKAGE = "com.supernote.document";

    @Override
    public void handleLoadPackage(
        XC_LoadPackage.LoadPackageParam loadPackageParam
    ) {
        if (loadPackageParam == null
            || !TARGET_PACKAGE.equals(loadPackageParam.packageName)
            || !TARGET_PACKAGE.equals(loadPackageParam.processName)) {
            return;
        }

        try {
            NativeReaderV2PackageAdmission.Report packageReport =
                NativeReaderV2PackageAdmission.verify(
                    new File(
                        NativeReaderV2PackageAdmission.EXPECTED_APK_PATH
                    ),
                    Build.FINGERPRINT
                );
            NativeReaderFirmwareAdmission.Report firmwareReport =
                NativeReaderFirmwareAdmission.verify(
                    loadPackageParam.classLoader
                );
            NativeReaderV2Hooks.install(loadPackageParam.classLoader);
            log("admitted contract=" + firmwareReport.contractId
                + " symbols=" + firmwareReport.symbolCount
                + " symbol_digest=" + firmwareReport.symbolDigest
                + " apk_sha256=" + packageReport.apkSha256
                + " apk_device=" + packageReport.device
                + " apk_inode=" + packageReport.inode);
        } catch (Throwable failure) {
            log("rejected; no hooks installed: " + failure);
            XposedBridge.log(failure);
        }
    }

    private static void log(String message) {
        XposedBridge.log("SN_NATIVE_READER_V2_ENTRY " + message);
    }
}
