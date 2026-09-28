package com.techrebbe.supernote.disposableleasehost;

/** Pure-Java, fixed host vocabulary; no Android or document dependency. */
public final class ProbeContract {
    public static final String AUTHORITY =
            "com.techrebbe.supernote.disposableleasehost.probe";
    public static final int ROOT_ID = 0x71000001;
    public static final int EVENT_CAPACITY = 256;

    public static final class ChildSpec {
        public final int id;
        public final String name;
        public final boolean image;
        public final int column;
        public final int row;
        public final int color;

        private ChildSpec(int id, String name, boolean image, int column,
                int row, int color) {
            this.id = id;
            this.name = name;
            this.image = image;
            this.column = column;
            this.row = row;
            this.color = color;
        }
    }

    // The first three roles correspond only to synthetic PDF/digest/ink views.
    // There is no PDF reader, pen API, or storage operation in this host.
    private static final ChildSpec[] CHILDREN = {
        new ChildSpec(0x71000100, "pdf_surrogate", true, 0, 0, 0xff6d8caf),
        new ChildSpec(0x71000101, "digest_surrogate", false, 1, 0, 0xffe9ad58),
        new ChildSpec(0x71000102, "ink_surrogate", false, 2, 0, 0xff88bf85),
        new ChildSpec(0x71000103, "scale", false, 0, 1, 0xffab9bd3),
        new ChildSpec(0x71000104, "toolbar", false, 1, 1, 0xff8cc6c4),
        new ChildSpec(0x71000105, "navigation", false, 2, 1, 0xffd89caa),
        new ChildSpec(0x71000106, "status", false, 0, 2, 0xffc6c489),
        new ChildSpec(0x71000107, "overlay", false, 1, 2, 0xffb6a181),
        new ChildSpec(0x71000108, "footer", false, 2, 2, 0xffa7b9cf)
    };

    public static int childCount() { return CHILDREN.length; }
    public static ChildSpec childAt(int index) { return CHILDREN[index]; }

    private ProbeContract() { }
}
