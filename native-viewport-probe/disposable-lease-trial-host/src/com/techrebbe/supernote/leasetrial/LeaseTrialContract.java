package com.techrebbe.supernote.leasetrial;

/** Fixed, synthetic API-30 emulator scene. No PDF or annotation file is opened. */
public final class LeaseTrialContract {
    public static final String PACKAGE = "com.techrebbe.supernote.leasetrial";
    public static final String AUTHORITY = PACKAGE + ".probe";
    public static final String STATE_SCHEMA = "lease-trial-no-child-state-v1";
    public static final String SCENE = "probe://disposable/no-child/page-1/render-0";
    public static final int ROOT_ID = 0x72000001;
    public static final int EVENT_CAPACITY = 256;

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
        new Child(0x72000100, "pdf_surrogate", 0xff6d8caf, 0, 0),
        new Child(0x72000101, "digest_surrogate", 0xffe9ad58, 1, 0),
        new Child(0x72000102, "ink_surrogate", 0xff88bf85, 2, 0),
        new Child(0x72000103, "scale", 0xffab9bd3, 0, 1),
        new Child(0x72000104, "toolbar", 0xff8cc6c4, 1, 1),
        new Child(0x72000105, "navigation", 0xffd89caa, 2, 1),
        new Child(0x72000106, "status", 0xffc6c489, 0, 2),
        new Child(0x72000107, "overlay", 0xffb6a181, 1, 2),
        new Child(0x72000108, "footer", 0xffa7b9cf, 2, 2)
    };

    public static int childCount() { return CHILDREN.length; }
    public static Child childAt(int index) { return CHILDREN[index]; }

    private LeaseTrialContract() { }
}
