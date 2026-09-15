# Pinned native-page firmware field map

Status: **read-only static evidence; not yet a hardware snapshot or runtime
manifest**.

This note records the exact field declarations that constrain the first
one-native-page observer. It deliberately replaces the earlier idea that each
role could be selected independently from flat fields. On the pinned Nomad
firmware, the useful page state is a direct-reference graph rooted at the one
foreground `DocumentActivity`.

## Evidence pins

- Authorized device: Nomad `SN078C10015092`.
- Firmware fingerprint:
  `Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`.
- `SupernoteDocument.apk` byte length: `138486560`.
- `SupernoteDocument.apk` SHA-256:
  `f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482`.
- `framework.jar` byte length: `30186065`.
- `framework.jar` SHA-256:
  `c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d`.

Both files were pulled read-only from the authorized device and inspected with
the installed Android APK analyzer. Static declarations establish names and
types only. They do not establish runtime values, uniqueness, index base,
semantic meaning, or lifecycle stability.

## Exact direct-reference graph

The concrete foreground root is:

`com.supernote.document.document.DocumentActivity`

Its relevant direct fields are:

| Field | Declared type |
| --- | --- |
| `documentViewModel` | `com.supernote.document.document.DocumentViewModel` |
| `handWritePresenter` | `com.supernote.document.handwrite.HandWritePresenter` |
| `handWriteView` | `com.supernote.document.handwrite.HandWriteView` |
| `mImage` | `com.supernote.document.utils.view.DocumentImageView` |
| `digestImage` | `com.supernote.document.utils.view.DigestImageView` |
| `mContentView` | `android.view.View` |
| `documentViewLayout` | `android.widget.RelativeLayout` |

The page ViewModel is
`com.supernote.document.document.DocumentViewModel`:

| Field | Declared type |
| --- | --- |
| `currentPage` | `int` |
| `pageCount` | `int` |
| `pageInfo` | `com.supernote.document.document.PageInfo` |
| `pageInfoHashMap` | `java.util.HashMap` |
| `documentAnnotationMap` | `java.util.Map` |
| `mupdf` | `com.supernote.document.document.DocumentMupdf` |
| `uri` | `android.net.Uri` |
| `scaleRect` | `android.graphics.RectF` |
| `portraitScaleRect` | `android.graphics.RectF` |
| `landscapeScaleRect` | `android.graphics.RectF` |
| `showRect` | `android.graphics.RectF` |
| `trimmingRect` | `android.graphics.RectF` |
| `landscapeTrimmingRect` | `android.graphics.RectF` |

The current page object is `com.supernote.document.document.PageInfo`:

| Field | Declared type |
| --- | --- |
| `page` | `int` |
| `ctm` | `com.artifex.mupdf.fitz.Matrix` |
| `revertCtm` | `com.artifex.mupdf.fitz.Matrix` |
| `originBitmap` | `android.graphics.Bitmap` |
| `displayBitmap` | `android.graphics.Bitmap` |
| `digestBitmap` | `android.graphics.Bitmap` |
| `offsetX` | `int` |
| `offsetY` | `int` |
| `trimmingRect` | `android.graphics.RectF` |
| `scale` | `float` |
| `location` | `com.artifex.mupdf.fitz.Location` |
| `pdfPage` | `com.artifex.mupdf.fitz.PDFPage` |
| `pagePosition` | `com.supernote.document.document.DocumentChapterPagePositionCache$PagePosition` |
| `links` | `com.artifex.mupdf.fitz.Link[]` |
| `digests` | `java.util.List` |

Each MuPDF matrix has direct finite-float candidates `a`, `b`, `c`, `d`, `e`
and `f`. Each `RectF` has direct public floats `left`, `top`, `right` and
`bottom`. Each `Bitmap` has direct `int mWidth`, `int mHeight`, and
`long mNativePtr` fields on this framework build. The native pointer is useful
only as an in-process same-sample identity hint; it is not a stable persisted
identity.

The handwriting presenter is
`com.supernote.document.handwrite.HandWritePresenter`:

| Field | Declared type |
| --- | --- |
| `currentPage` | `int` |
| `markPath` | `java.lang.String` |
| `screenRotation` | `int` |
| `bitmap` | `android.graphics.Bitmap` |
| `superNoteNote` | `com.example.libsupernote.SuperNoteNote` |
| `handWriteClient` | `com.supernote.document.handwrite.HandWriteClient` |
| `view` | `com.supernote.document.handwrite.HandWriteContract$View` |
| `uri` | `android.net.Uri` |

That `HandWriteClient` has direct `android.os.IBinder iBinder` and
`android.os.IBinder mSFBinder` fields. `SuperNoteNote` has a direct
`long pointer` field. These values may bind the retained runtime graph within
one observation, but their stability and relationship to DrawPath still require
hardware evidence.

For a concrete `android.net.Uri$StringUri`, the framework exposes direct final
`java.lang.String uriString`. The runtime URI subtype must be checked. No
observer may invoke `Uri.toString()` or infer a path if the object is another
subtype.

Inherited `android.app.Activity` fields include `mToken`, `mFinished`,
`mDestroyed`, and `mResumed`. There is no direct task-ID or display-ID field on
the pinned class. Task, display, process start time, and diagnostic session
generation therefore remain external coordinator authorities and must not be
invented as target fields.

The pinned framework's inherited `android.view.View` fields include direct
integer `mLeft`, `mTop`, `mRight`, `mBottom`, `mScrollX`, `mScrollY`, and
`mWindowAttachCount`, plus `android.view.View$AttachInfo mAttachInfo`. The v2
observer can therefore compare the page image, handwriting overlay, digest
overlay, content view, and document container bounds without invoking a View
getter. This is raw layout evidence only; display identity remains external.

## Required observer revision

The first observer prototype cannot be hardware-enabled with a synthetic flat
manifest. Its replacement must:

1. enumerate exactly one concrete `DocumentActivity` under the externally
   authenticated process/task/display session;
2. retain that root and traverse only the direct references documented above;
3. read the same retained graph twice rather than performing independent heap
   searches for ViewModel, PageInfo, presenter, note, client, matrices, rects,
   bitmaps, or URI;
4. reject null, wrong-class, replacement, wrapper-shaped, nonfinite, singular,
   out-of-range, or cross-page values;
5. bind external task/display/session evidence without claiming those values
   came from unavailable Activity fields;
6. keep layer identities explicitly unavailable until their exact direct
   provenance is established; and
7. emit no runtime snapshot until the URI subtype, page index base, page/count
   relationship, matrix semantics, bitmap roles, presenter/ViewModel agreement,
   Binder identities, and lifecycle stability have each passed a read-only
   hardware probe.

The external runner must still authenticate and revalidate the APK, native
module, original PDF, nullable `.mark`, URI resolution, PID/start-time, task,
display, script, and canonical manifest before and after detach. Static field
availability weakens none of those requirements.

## Explicit non-claims

This evidence does not prove that:

- `currentPage` or `PageInfo.page` is zero-based;
- `ctm` is the source-to-native presentation transform;
- `revertCtm` is its correct inverse in every rotation/crop mode;
- any bitmap is the committed handwriting layer rather than a composite;
- `screenRotation` has a known enum meaning;
- Binder or native-pointer values are stable across a reload; or
- a native page can write correctly inside an arbitrary viewport.

Those are hardware gates. No source file, annotation, installed package, reader
state, or input device was modified to obtain this static map.
