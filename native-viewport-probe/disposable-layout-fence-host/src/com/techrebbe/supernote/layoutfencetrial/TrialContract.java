package com.techrebbe.supernote.layoutfencetrial;

/** Fixed synthetic scene, deliberately unrelated to any reader or document. */
public final class TrialContract {
    public static final String PACKAGE = "com.techrebbe.supernote.layoutfencetrial";
    public static final String AUTHORITY = PACKAGE + ".probe";
    public static final String SCHEMA = "layout-fence-synthetic-v1";
    public static final String SCENE = "probe://disposable/layout-fence/nine";
    public static final String REVISION_SCOPE = "PARENT_LAYOUT_CALL_ONLY";
    public static final int ROOT_ID = 0x73000001;
    public static final int PARENT_ID = 0x73000002;
    public static final int EVENT_CAPACITY = 256;
    public static final long MAIN_DISPATCH_TIMEOUT_MS = 3000;
    public static final long HARD_STOP_GRACE_MS = 2000;

    public static final class Child {
        public final int id;
        public final String name;
        public final int color;
        public final int column;
        public final int row;

        private Child(int id, String name, int color, int column, int row) {
            this.id = id;
            this.name = name;
            this.color = color;
            this.column = column;
            this.row = row;
        }
    }

    private static final Child[] CHILDREN = {
        new Child(0x73000100, "tile_0", 0xff6d8caf, 0, 0),
        new Child(0x73000101, "tile_1", 0xffe9ad58, 1, 0),
        new Child(0x73000102, "tile_2", 0xff88bf85, 2, 0),
        new Child(0x73000103, "tile_3", 0xffab9bd3, 0, 1),
        new Child(0x73000104, "tile_4", 0xff8cc6c4, 1, 1),
        new Child(0x73000105, "tile_5", 0xffd89caa, 2, 1),
        new Child(0x73000106, "tile_6", 0xffc6c489, 0, 2),
        new Child(0x73000107, "tile_7", 0xffb6a181, 1, 2),
        new Child(0x73000108, "tile_8", 0xffa7b9cf, 2, 2)
    };

    public static int childCount() { return CHILDREN.length; }
    public static Child childAt(int index) { return CHILDREN[index]; }

    /** `adb shell content call --extra key:s:value` cannot carry colons in value. */
    static String rootToken(String incarnation, String nonce) {
        if (incarnation == null || nonce == null
                || !incarnation.matches("[A-Za-z0-9_-]+")
                || !nonce.matches("[A-Za-z0-9_-]+")) {
            throw new IllegalArgumentException("wire-safe root token components required");
        }
        return incarnation + "-root-" + nonce;
    }

    private TrialContract() { }
}
