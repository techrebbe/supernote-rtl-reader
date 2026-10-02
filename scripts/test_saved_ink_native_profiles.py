#!/usr/bin/env python3
"""Compile actual saved-ink templates; exercise bounded source/profile/lease checks.

Standard-library wrapper, cached Kotlin 2.0.21 and JDK 17. With --fixture no
Python packages are required; the default fixture generator needs reportlab and
pypdf. Android stubs model
descriptor/path replacement and queued main-thread draining, not a PDF renderer,
device, writer, save witness or ink-registration pass. All generated inputs and
classes stay in an owned temporary directory; repository/device files are not
changed. SavedInkModule is compiled and cleanup fences are checked in its actual
source, but its file-writing/SDK workflow is deliberately not executed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile


FIXTURE_SHA256 = "bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64"
PACKAGE = "nativeprofilestest"

STUBS = {
    "System.kt": r'''
package android.system
import java.io.File
import java.io.FileDescriptor
import java.util.IdentityHashMap

class ErrnoException(val functionName: String, val errno: Int) : Exception(functionName)
data class StructStat(val st_dev: Long, val st_ino: Long, val st_mode: Int,
    val st_size: Long, val st_mtime: Long, val st_ctime: Long)
object OsConstants {
    const val O_RDONLY = 0
    const val O_NOFOLLOW = 0x20000
    const val ENOENT = 2
    const val ELOOP = 40
    const val S_IFREG = 0x8000
    const val S_IFDIR = 0x4000
    const val S_IFLNK = 0xa000
    fun S_ISREG(mode: Int) = mode and 0xf000 == S_IFREG
    fun S_ISDIR(mode: Int) = mode and 0xf000 == S_IFDIR
}
object Os {
    data class Node(var bytes: ByteArray, var device: Long = 1, var inode: Long = 101,
        var mtime: Long = 7, var ctime: Long = 8, var mode: Int = OsConstants.S_IFREG,
        var reportedSize: Long = bytes.size.toLong()) {
        fun stat() = StructStat(device, inode, mode, reportedSize, mtime, ctime)
    }
    private data class Open(val node: Node, var position: Long = 0)
    private val paths = HashMap<String, Node>()
    private val opened = IdentityHashMap<FileDescriptor, Open>()
    var noFollowOpens = 0
    var preadCalls = 0
    var beforePread: (() -> Unit)? = null
    var shortReadLimit = Int.MAX_VALUE
    var statCalls = 0
    var openCalls = 0
    fun clear() {
        paths.clear(); opened.clear(); noFollowOpens = 0; preadCalls = 0
        beforePread = null; shortReadLimit = Int.MAX_VALUE; statCalls = 0; openCalls = 0
    }
    fun map(path: String, node: Node) {
        paths[path] = node
        paths[File(path).absolutePath] = node
        paths[File(path).canonicalPath] = node
    }
    fun lstat(path: String): StructStat {
        statCalls++
        return (paths[path] ?: throw ErrnoException("lstat", OsConstants.ENOENT)).stat()
    }
    fun open(path: String, flags: Int, mode: Int): FileDescriptor {
        openCalls++
        require(flags and OsConstants.O_NOFOLLOW != 0) { "Test requires O_NOFOLLOW" }
        noFollowOpens++
        val node = paths[path] ?: throw ErrnoException("open", OsConstants.ENOENT)
        if (node.mode == OsConstants.S_IFLNK) throw ErrnoException("open", OsConstants.ELOOP)
        return descriptor(node)
    }
    fun descriptor(node: Node): FileDescriptor = FileDescriptor().also { opened[it] = Open(node) }
    fun dup(fd: FileDescriptor): FileDescriptor = descriptor(opened[fd]?.node ?: error("Closed fd"))
    fun fstat(fd: FileDescriptor): StructStat = (opened[fd] ?: error("Closed fd")).node.stat()
    fun close(fd: FileDescriptor) { opened.remove(fd) }
    fun position(fd: FileDescriptor): Long = (opened[fd] ?: error("Closed fd")).position
    fun seek(fd: FileDescriptor, position: Long) { (opened[fd] ?: error("Closed fd")).position = position }
    fun pread(fd: FileDescriptor, target: ByteArray, offset: Int, count: Int, position: Long): Int {
        preadCalls++
        val hook = beforePread; beforePread = null; hook?.invoke()
        val data = (opened[fd] ?: error("Closed fd")).node.bytes
        if (position >= data.size) return 0
        val amount = minOf(count, data.size - position.toInt(), shortReadLimit)
        data.copyInto(target, offset, position.toInt(), position.toInt() + amount)
        return amount
    }
}
''',
    "Os.kt": r'''
package android.os
import android.system.Os
import java.io.FileDescriptor
import java.util.ArrayDeque

class Looper private constructor() {
    companion object {
        private val main = Looper()
        var onMain = true
        fun getMainLooper() = main
        fun myLooper(): Looper? = if (onMain) main else null
    }
}
object TestLoop {
    var accept = true
    private val queue = ArrayDeque<() -> Unit>()
    fun enqueue(work: () -> Unit): Boolean { if (!accept) return false; queue.add(work); return true }
    fun flush() {
        check(Looper.onMain)
        while (queue.isNotEmpty()) queue.removeFirst().invoke()
    }
}
class Handler(looper: Looper) { fun post(work: () -> Unit) = TestLoop.enqueue(work) }
class ParcelFileDescriptor(val fileDescriptor: FileDescriptor) : AutoCloseable {
    override fun close() { Os.close(fileDescriptor) }
    companion object { fun dup(fd: FileDescriptor) = ParcelFileDescriptor(Os.dup(fd)) }
}
''',
    "Graphics.kt": r'''
package android.graphics
class Bitmap(val width: Int, val height: Int, val isMutable: Boolean = false) {
    var isRecycled = false
        private set
    var recycleCount = 0
        private set
    fun recycle() { check(!isRecycled); isRecycled = true; recycleCount++ }
    fun hasAlpha() = true
    fun getPixels(target: IntArray, offset: Int, stride: Int, x: Int, y: Int, width: Int, height: Int) {
        error("Module bitmap decoding is compile-only in this bounded harness")
    }
    enum class Config { ARGB_8888 }
}
object BitmapFactory {
    class Options {
        var inJustDecodeBounds = false; var outMimeType: String? = null
        var outWidth = 0; var outHeight = 0; var inMutable = false
        var inPreferredConfig: Bitmap.Config? = null
    }
    fun decodeByteArray(bytes: ByteArray, offset: Int, length: Int, options: Options): Bitmap? =
        error("Module decoding is compile-only")
}
''',
    "Pdf.kt": r'''
package android.graphics.pdf
import android.os.ParcelFileDescriptor
object TestPdf {
    var count = 2; var width = 612; var height = 792
    var openedPage = -1; var rendererCloses = 0; var pageCloses = 0
    fun reset() { count = 2; width = 612; height = 792; openedPage = -1; rendererCloses = 0; pageCloses = 0 }
}
class PdfRenderer(val parcel: ParcelFileDescriptor) : AutoCloseable {
    val pageCount get() = TestPdf.count
    fun openPage(index: Int): Page { TestPdf.openedPage = index; return Page() }
    class Page : AutoCloseable {
        val width get() = TestPdf.width
        val height get() = TestPdf.height
        override fun close() { TestPdf.pageCloses++ }
    }
    override fun close() { TestPdf.rendererCloses++ }
}
''',
    "Log.kt": r'''
package android.util
object Log {
    fun w(tag: String, message: String) = 0
    fun e(tag: String, message: String) = 0
    fun e(tag: String, message: String, error: Throwable) = 0
}
''',
    "React.kt": r'''
package com.facebook.react.bridge
import java.io.File
annotation class ReactMethod
class ReactApplicationContext(val filesDir: File)
open class ReactContextBaseJavaModule(val reactApplicationContext: ReactApplicationContext) {
    open fun getName(): String = "stub"
    open fun invalidate() {}
}
interface Promise {
    fun resolve(value: Any?)
    fun reject(code: String, message: String?)
    fun reject(code: String, message: String?, error: Throwable)
}
class WritableMap {
    fun putString(key: String, value: String?) {}
    fun putInt(key: String, value: Int) {}
    fun putDouble(key: String, value: Double) {}
    fun putBoolean(key: String, value: Boolean) {}
}
object Arguments { fun createMap() = WritableMap() }
''',
}

HARNESS = r'''
package nativeprofilestest
import android.graphics.Bitmap
import android.graphics.pdf.TestPdf
import android.os.Looper
import android.os.TestLoop
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.util.UUID

object SavedInkNativeProfilesTest {
    private var checks = 0
    private var groups = 0
    private lateinit var fixture: ByteArray
    private fun check(value: Boolean, label: String) { checks++; if (!value) throw AssertionError(label) }
    private fun fails(label: String, action: () -> Unit) {
        checks++
        try { action() } catch (_: Exception) { return }
        throw AssertionError("Accepted invalid case: $label")
    }
    private fun reset(): Os.Node {
        Os.clear(); TestPdf.reset()
        val node = Os.Node(fixture.copyOf())
        Os.map(SavedInkProfiles.T008_PATH, node)
        return node
    }
    private fun verified() = SavedInkProfiles.verifyBackground(SavedInkProfiles.T008_PATH, 0)
        ?: throw AssertionError("Missing T008 background")

    private fun profiles() {
        val a = SavedInkProfiles.requireProfile(SavedInkProfiles.T004_ID, SavedInkProfiles.T004_PATH, 2)
        val b = SavedInkProfiles.requireProfile(SavedInkProfiles.T008_ID, SavedInkProfiles.T008_PATH, 0)
        check(a.id == "t004-page3-canvas-v1" && b.id == "t008-page1-stock-portrait-fit-v1", "exact ids")
        check(a.pageCount == 8 && b.pageCount == 2, "exact counts")
        check(a.width == 1404 && a.height == 1872 && b.width == 1404 && b.height == 1872, "full canvas")
        check(b.sourceSha256 == "bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64", "exact source SHA")
        check(b.geometry.innerWidth == 1404 && b.geometry.innerHeight == 1817, "stock fitted rectangle")
        check(b.geometry.offsetX == 0 && b.geometry.offsetY == 27, "stock integer offsets")
        check(b.geometry.canvasWidth == 1404 && b.geometry.canvasHeight == 1872, "padded canvas")
        check(b.geometry.ctmScale.toRawBits() == 0x4012d2d3, "stock binary32 CTM")
        check(a.metadata == null, "T004 has no new PDF metadata authority")
        check(b.metadata?.mediaBox == SavedInkProfiles.Box(0, 0, 612, 792) &&
            b.metadata?.cropBox == b.metadata?.mediaBox && b.metadata?.rotation == 0 &&
            b.metadata?.userUnit == 1, "strict vetted metadata")
        check(SavedInkProfiles.profileById("unknown") == null, "unknown profile")
        fails("unknown id") { SavedInkProfiles.requireProfile("unknown", b.filePath, 0) }
        fails("profile/source mismatch") { SavedInkProfiles.requireProfile(a.id, b.filePath, 2) }
        fails("page2") { SavedInkProfiles.requireProfile(b.id, b.filePath, 1) }
        fails("other path") { SavedInkProfiles.requireProfile(b.id, b.filePath + ".copy", 0) }
        fails("path alias spelling") { SavedInkProfiles.requireProfile(b.id, b.filePath.replace("/Document/", "/Document/./"), 0) }
        Os.clear()
        check(SavedInkProfiles.verifyBackground(a.filePath, 2) == null, "T004 background unchanged")
        check(SavedInkProfiles.verifyBackground(b.filePath, 1) == null, "PAGE2 uses default background")
        check(SavedInkProfiles.verifyBackground(b.filePath + ".copy", 0) == null, "other source default background")
        check(Os.openCalls == 0 && Os.statCalls == 0, "unsupported backgrounds do not read sources")
        groups++
    }

    private fun background() {
        val node = reset()
        val result = verified()
        check(result.id == SavedInkProfiles.T008_ID, "verified geometry identity")
        check(result.stamp.length == fixture.size.toLong() && result.stamp.modified == 0L &&
            result.stamp.device == node.device && result.stamp.inode == node.inode &&
            result.stamp.mtime == node.mtime && result.stamp.ctime == node.ctime, "source stamp")
        check(TestPdf.openedPage == 0 && TestPdf.pageCloses == 1 && TestPdf.rendererCloses == 1, "metadata page and closure")
        val fd = Os.open(SavedInkProfiles.T008_PATH, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW, 0)
        Os.seek(fd, 37)
        Os.shortReadLimit = 7
        result.validateDescriptor(fd)
        check(Os.position(fd) == 37L, "pread preserves descriptor position")
        Os.close(fd)
        result.validatePath()
        check(Os.openCalls == Os.noFollowOpens, "every reopen is NOFOLLOW")
        check(Os.preadCalls > 4, "descriptor hashes bytes through repeated pread")
        groups++
    }

    private fun backgroundRejections() {
        reset().bytes[0] = (fixture[0].toInt() xor 1).toByte()
        fails("wrong source SHA") { verified() }
        reset().reportedSize = 0
        fails("empty source") { verified() }
        reset().reportedSize = 32L * 1024 * 1024 + 1
        fails("over source bound") { verified() }
        reset().mode = OsConstants.S_IFLNK
        fails("symlink source") { verified() }
        reset().mode = OsConstants.S_IFDIR
        fails("directory source") { verified() }
        reset(); TestPdf.count = 3
        fails("page count") { verified() }
        check(TestPdf.rendererCloses == 1, "renderer closes on count rejection")
        reset(); TestPdf.width = 613
        fails("page width") { verified() }
        check(TestPdf.pageCloses == 1 && TestPdf.rendererCloses == 1, "page closes on width rejection")
        reset(); TestPdf.height = 793
        fails("page height") { verified() }

        val original = reset(); val result = verified()
        val replacementFd = Os.descriptor(original.copy(inode = original.inode + 1))
        fails("replacement descriptor") { result.validateDescriptor(replacementFd) }
        Os.close(replacementFd)
        val wrongTypeFd = Os.descriptor(original.copy(mode = OsConstants.S_IFDIR))
        fails("nonregular descriptor") { result.validateDescriptor(wrongTypeFd) }
        Os.close(wrongTypeFd)
        val wrongShaFd = Os.descriptor(original.copy(bytes = fixture.copyOf().also { it[0] = 0 }))
        fails("descriptor same-stamp wrong SHA") { result.validateDescriptor(wrongShaFd) }
        Os.close(wrongShaFd)
        Os.map(SavedInkProfiles.T008_PATH, original.copy(inode = original.inode + 1))
        fails("replacement path") { result.validatePath() }

        val unchanged = reset(); val sameStamp = verified()
        unchanged.bytes[0] = (fixture[0].toInt() xor 1).toByte()
        fails("path same-stamp wrong SHA") { sameStamp.validatePath() }
        val changedDuringRead = reset(); val before = verified()
        val fd = Os.open(SavedInkProfiles.T008_PATH, OsConstants.O_NOFOLLOW, 0)
        Os.beforePread = { changedDuringRead.ctime++ }
        fails("stamp changes during descriptor hash") { before.validateDescriptor(fd) }
        Os.close(fd)
        reset(); Os.shortReadLimit = 0
        fails("premature pread EOF") { verified() }
        reset().reportedSize = fixture.size.toLong() - 1
        fails("bytes beyond snapshot length") { verified() }
        groups++
    }

    private fun stamp(path: String, node: Os.Node) = SavedInkRegistry.SourceStamp(
        File(path).canonicalPath, node.reportedSize, 0, node.device, node.inode, node.mtime, node.ctime)
    private data class Ink(val token: String, val bitmap: Bitmap,
        val source: SavedInkRegistry.SourceStamp, val annotation: SavedInkRegistry.SourceStamp)
    private fun ink(id: String): Ink {
        check(SavedInkRegistry.isEmpty(), "clean registry before publication")
        Os.clear()
        val profile = SavedInkProfiles.profileById(id) ?: error("bad harness profile")
        val pdf = Os.Node(byteArrayOf(1, 2, 3), inode = 200)
        val mark = Os.Node(byteArrayOf(4, 5, 6), inode = 201)
        Os.map(profile.filePath, pdf); Os.map(profile.filePath + ".mark", mark)
        val source = stamp(profile.filePath, pdf); val annotation = stamp(profile.filePath + ".mark", mark)
        val bitmap = Bitmap(1404, 1872)
        val token = UUID.randomUUID().toString()
        SavedInkRegistry.publish(token, bitmap, source, annotation, profile.pageIndex, id)
        return Ink(token, bitmap, source, annotation)
    }
    private fun match(lease: SavedInkRegistry.Lease, ink: Ink, page: Int, width: Int,
        height: Int, geometry: String? = null) = lease.matches(ink.source.canonicalPath,
        ink.source.length, ink.source.modified, page, width, height, geometry)
    private fun drain(ink: Ink) {
        SavedInkRegistry.revoke(ink.token)
        var acknowledged: Boolean? = null
        SavedInkRegistry.drainRevoked(ink.token) { acknowledged = it }
        check(acknowledged == null, "drain requires queued main-thread boundary")
        TestLoop.flush()
        check(acknowledged == true && SavedInkRegistry.isEmpty(), "drain ACK empties registry")
        check(ink.bitmap.isRecycled && ink.bitmap.recycleCount == 1, "bitmap recycled exactly once")
    }

    private fun registryShapes() {
        val old = ink(SavedInkProfiles.T004_ID)
        val a = SavedInkRegistry.acquire(old.token) ?: error("missing T004 lease")
        check(match(a, old, 2, 900, 1200), "T004 scaled 3:4 legacy")
        check(match(a, old, 2, 1404, 1873), "T004 one-pixel legacy tolerance")
        check(match(a, old, 2, 1404, 1872, SavedInkProfiles.T004_ID), "T004 explicit identity")
        check(!match(a, old, 2, 1404, 1817), "T004 rejects another aspect")
        check(!match(a, old, 2, 1404, 1872, SavedInkProfiles.T008_ID), "T004 rejects foreign identity")
        drain(old)
        check(!a.matchesPage(SavedInkProfiles.T004_PATH, 2), "released T004 lease cannot draw")

        val current = ink(SavedInkProfiles.T008_ID)
        val b = SavedInkRegistry.acquire(current.token) ?: error("missing T008 lease")
        check(match(b, current, 0, 1404, 1872, SavedInkProfiles.T008_ID), "T008 padded full canvas")
        check(!match(b, current, 0, 1404, 1872), "T008 bare background rejected")
        check(!match(b, current, 0, 1404, 1817, SavedInkProfiles.T008_ID), "T008 inner bitmap rejected")
        check(!match(b, current, 0, 900, 1200, SavedInkProfiles.T008_ID), "T008 scaled source raster rejected")
        check(!match(b, current, 1, 1404, 1872, SavedInkProfiles.T008_ID), "wrong ink page rejected")
        check(!match(b, current, 0, 1404, 1872, SavedInkProfiles.T004_ID), "T008 foreign identity rejected")
        check(!b.matches("other", current.source.length, 0, 0, 1404, 1872, SavedInkProfiles.T008_ID), "wrong source path")
        check(!b.matches(current.source.canonicalPath, current.source.length + 1, 0, 0, 1404, 1872, SavedInkProfiles.T008_ID), "wrong source length")
        Os.map(SavedInkProfiles.T008_PATH + ".mark", Os.Node(byteArrayOf(4, 5, 6), inode = 999))
        check(!match(b, current, 0, 1404, 1872, SavedInkProfiles.T008_ID), "replaced mark invalidates lease")
        drain(current)
        groups++
    }

    private fun registryOwnership() {
        val current = ink(SavedInkProfiles.T008_ID)
        val first = SavedInkRegistry.acquire(current.token) ?: error("missing first lease")
        val second = SavedInkRegistry.acquire(current.token) ?: error("missing second lease")
        var ownedDrain: Boolean? = null
        SavedInkRegistry.drainRevoked(current.token) { ownedDrain = it }
        TestLoop.flush()
        check(ownedDrain == false && !current.bitmap.isRecycled, "never drain still-owned ink")
        val rejected = Bitmap(1404, 1872)
        fails("overlapping publication") {
            SavedInkRegistry.publish(UUID.randomUUID().toString(), rejected, current.source,
                current.annotation, 0, SavedInkProfiles.T008_ID)
        }
        check(!rejected.isRecycled, "failed publication does not take caller bitmap")
        rejected.recycle()
        Looper.onMain = false
        fails("acquire off main") { SavedInkRegistry.acquire(current.token) }
        fails("release off main") { first.release() }
        Looper.onMain = true
        SavedInkRegistry.revoke(current.token)
        check(SavedInkRegistry.acquire(current.token) == null, "revoked owner cannot issue new lease")
        check(!current.bitmap.isRecycled && !SavedInkRegistry.isEmpty(), "two leases retain revoked bitmap")
        check(!first.matchesPage(SavedInkProfiles.T008_PATH, 0), "revoked lease hidden immediately")
        first.release()
        check(!current.bitmap.isRecycled, "second lease still holds bitmap")
        TestLoop.accept = false
        var rejectedDrain: Boolean? = null
        SavedInkRegistry.drainRevoked(current.token) { rejectedDrain = it }
        check(rejectedDrain == false && !current.bitmap.isRecycled, "rejected main post is not cleanup success")
        TestLoop.accept = true
        drain(current)
        second.release(); first.release()
        check(current.bitmap.recycleCount == 1, "lease release idempotent")
        groups++
    }

    private fun registryRejections() {
        val base = ink(SavedInkProfiles.T008_ID); drain(base)
        fun reject(label: String, bitmap: Bitmap = Bitmap(1404, 1872),
            source: SavedInkRegistry.SourceStamp = base.source,
            annotation: SavedInkRegistry.SourceStamp? = base.annotation,
            page: Int = 0, id: String = SavedInkProfiles.T008_ID,
            token: String = UUID.randomUUID().toString()) {
            fails(label) { SavedInkRegistry.publish(token, bitmap, source, annotation, page, id) }
            check(SavedInkRegistry.isEmpty(), "rejection retains no registry entry")
        }
        reject("unknown geometry", id = "unknown")
        reject("wrong page", page = 1)
        reject("wrong source", source = base.source.copy(canonicalPath = "other"))
        reject("missing sidecar", annotation = null)
        reject("other sidecar", annotation = base.annotation.copy(canonicalPath = "other.mark"))
        reject("wrong bitmap width", bitmap = Bitmap(1403, 1872))
        reject("wrong bitmap height", bitmap = Bitmap(1404, 1817))
        reject("mutable bitmap", bitmap = Bitmap(1404, 1872, true))
        reject("recycled bitmap", bitmap = Bitmap(1404, 1872).also { it.recycle() })
        reject("malformed token", token = "not-a-uuid")
        groups++
    }

    @JvmStatic fun main(args: Array<String>) {
        fixture = File(args.single()).readBytes()
        profiles(); background(); backgroundRejections(); registryShapes(); registryOwnership(); registryRejections()
        println("PASS: $groups groups, $checks runtime checks; actual Profiles/Registry + Module compile; no hardware/ink pass")
    }
}
'''


def cached_jar(cache: Path, group: str, artifact: str, version: str) -> Path:
    matches = list((cache / group / artifact / version).glob(f"*/{artifact}-{version}.jar"))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one cached {group}:{artifact}:{version}, found {len(matches)}")
    return matches[0]


def compiler_jars(cache: Path) -> tuple[list[Path], Path]:
    coordinates = [
        ("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.0.21"),
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.0.21"),
        ("org.jetbrains.kotlin", "kotlin-script-runtime", "2.0.21"),
        ("org.jetbrains.kotlin", "kotlin-reflect", "1.6.10"),
        ("org.jetbrains.kotlin", "kotlin-daemon-embeddable", "2.0.21"),
        ("org.jetbrains.intellij.deps", "trove4j", "1.0.20200330"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.6.4"),
        ("org.jetbrains", "annotations", "13.0"),
    ]
    jars = [cached_jar(cache, *coordinate) for coordinate in coordinates]
    return jars, jars[1]


def source_fences(source: str) -> int:
    """Actual Module lifecycle is compile/source checked, never executed here."""
    rules = [
        (r"if\s*\(!request\.finished\)\s*\{[\s\S]*?return@forEach", "retain unfinished SDK output"),
        (r"closed\.compareAndSet\(false,\s*true\)", "invalidate owns single shutdown"),
        (r"alphaMin\s*==\s*0\s*&&\s*alphaMax\s*>\s*0", "transparent background and visible ink"),
        (r"request\.background\?\.validatePath\(\)", "profile source rechecked at finish"),
        (r"require\(requests\.isEmpty\(\)\s*&&\s*SavedInkRegistry\.isEmpty\(\)\)", "no overlapping owner"),
    ]
    for pattern, label in rules:
        if not re.search(pattern, source):
            raise AssertionError(f"Module fence missing: {label}")
    discard = source.split("fun discard(", 1)[1].split("override fun invalidate", 1)[0]
    if not (discard.index("removeOwned(request)") < discard.index("drainRevoked(")
            < discard.index('putBoolean("discarded", true)')):
        raise AssertionError("discard must await main-thread drain before ACK")
    if 'promise.reject("SAVED_INK_REJECTED", "Saved-ink UI drain could not be verified")' not in discard:
        raise AssertionError("unconfirmed drain must reject discard")
    return len(rules) + 2


def jdk_tools(home: Path) -> tuple[Path, Path]:
    suffix = ".exe" if os.name == "nt" else ""
    javac, java = [home / "bin" / (name + suffix) for name in ("javac", "java")]
    for executable in (javac, java):
        result = subprocess.run([str(executable), "-version"], capture_output=True,
                                text=True, timeout=10, check=True)
        if not re.search(r'(?:javac\s+|version\s+")17(?:[.\s"]|$)', result.stdout + result.stderr):
            raise RuntimeError("JDK 17 is required")
    return javac, java


def fixture_bytes(root: Path, temp: Path, supplied: Path | None) -> bytes:
    if supplied:
        value = supplied.read_bytes()
    else:
        import sys
        generated = temp / "generated" / "disposable-source.pdf"
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / "build_saved_ink_geometry_fixture.py"), str(generated)],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if result.returncode != 0:
            raise RuntimeError(
                "Cannot generate the exact disposable fixture (reportlab+pypdf required). "
                "Pass --fixture pointing to the existing SHA-checked T008 PDF.\n" + result.stderr
            )
        value = generated.read_bytes()
    if hashlib.sha256(value).hexdigest() != FIXTURE_SHA256:
        raise RuntimeError("Exact T008 disposable fixture bytes are required; PDF SHA differs from native profile")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--fixture", type=Path, help="Optional exact disposable PDF; SHA must match native profile")
    parser.add_argument("--jdk-home", type=Path, default=Path(os.environ.get("JAVA_HOME", "C:/Program Files/Java/jdk-17")))
    parser.add_argument("--gradle-cache", type=Path,
                        default=Path.home() / ".gradle/caches/modules-2/files-2.1")
    args = parser.parse_args()
    root = args.root.resolve()
    javac, java = jdk_tools(args.jdk_home)
    jars, stdlib = compiler_jars(args.gradle_cache)
    with tempfile.TemporaryDirectory(prefix="rtl-saved-ink-native-profiles-") as folder:
        temp = Path(folder)
        fixture = fixture_bytes(root, temp, args.fixture)
        classes = temp / "classes"
        classes.mkdir()
        marker = "package __PACKAGE__"
        for name in ("SavedInkProfiles", "SavedInkRegistry", "SavedInkModule", "SavedInkFitGeometry"):
            extension = "java" if name == "SavedInkFitGeometry" else "kt"
            source = (root / "native" / f"{name}.{extension}.template").read_text(encoding="utf-8")
            if source.count(marker) != 1:
                raise RuntimeError(f"Expected exactly one package marker in {name}")
            if name == "SavedInkModule":
                fence_count = source_fences(source)
            (temp / f"{name}.{extension}").write_text(source.replace(marker, f"package {PACKAGE}"), encoding="utf-8")
        for name, source in STUBS.items():
            (temp / name).write_text(source, encoding="utf-8")
        (temp / "SavedInkNativeProfilesTest.kt").write_text(HARNESS, encoding="utf-8")
        fixture_copy = temp / "disposable-source.pdf"
        fixture_copy.write_bytes(fixture)
        subprocess.run([str(javac), "--release", "8", "-d", str(classes),
                        str(temp / "SavedInkFitGeometry.java")], cwd=temp, check=True, timeout=30)
        classpath = os.pathsep.join([str(classes), str(stdlib), str(jars[-1])])
        compiler = [str(java), "-Xmx512m", "-cp", os.pathsep.join(map(str, jars)),
                    "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect",
                    "-jvm-target", "1.8", "-classpath", classpath, "-d", str(classes), "-nowarn"]
        subprocess.run(compiler + [str(path) for path in sorted(temp.glob("*.kt"))],
                       cwd=temp, check=True, timeout=60)
        subprocess.run([str(java), "-ea", "-cp", classpath,
                        f"{PACKAGE}.SavedInkNativeProfilesTest", str(fixture_copy)],
                       cwd=temp, check=True, timeout=30)
        print(f"PASS: {fence_count} actual Module source cleanup/identity fences; no device/APK build")


if __name__ == "__main__":
    main()
