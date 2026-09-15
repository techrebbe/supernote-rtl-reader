package com.example.libsupernote;

import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.Rect;
import java.util.ArrayList;
import java.util.List;

/** Host-only record whose shape matches the pinned native trail contract. */
public final class GoldenTrailRecord {
    public int flag_penup, flag_special, font_height, font_width, layer_num;
    public int m_after_shift_angle, m_before_shift_angle, m_copy, m_draw_version;
    public int m_emr_point_axis, m_group_nest, m_group_num, m_mupdf_chapter;
    public int m_mupdf_offset_x, m_mupdf_offset_y, m_mupdf_position;
    public int m_redraw_height, m_redraw_width, m_rotate_angle, m_thickness;
    public int m_trail_father, m_trail_num_in_page, m_trail_status, m_trail_type;
    public int max_x, max_y, page_num, pen_color, pen_type, pre_num, process_mod;
    public int rec_mod, recogn_trail_type, trail_num, walcom_emr_type;

    public boolean m_filter_flag, m_group_end, m_recogn_flag, m_render_flag;
    public String m_custom_string = "custom-golden";
    public String m_link_image_string = "image-golden";
    public String m_link_info = "link-golden";
    public String m_userData = "slash=/ close=</ quote=\" backslash=\\"
        + " controls=\u0000\b\t\n\u000b\f\r\u001f del=\u007f c1=\u0085"
        + " separators=\u2028\u2029 hebrew=\u05e9\u05dc\u05d5\u05dd"
        + " combining=e\u0301 emoji=\ud83d\ude00";
    public String write_app_name = "writer-golden";

    public List<Object> angles = new ArrayList<Object>();
    public List<Object> disable_area_list = new ArrayList<Object>();
    public List<Object> erase_line_trail_num = new ArrayList<Object>();
    public List<Object> flag_draw = new ArrayList<Object>();
    public List<Object> m_contours_src = new ArrayList<Object>();
    public List<Object> m_control_nums = new ArrayList<Object>();
    public List<Object> m_hierarchy = new ArrayList<Object>();
    public List<Object> m_mark_pen_d_fill_dir = new ArrayList<Object>();
    public List<Object> m_points = new ArrayList<Object>();
    public List<Object> pressures = new ArrayList<Object>();
    public List<Object> recogn_points = new ArrayList<Object>();
    public List<Object> timestamp = new ArrayList<Object>();

    public Rect m_after_shift_rect = new Rect(301, 302, 303, 304);
    public Rect m_before_shift_rect = new Rect(305, 306, 307, 308);
    public Rect refresh_rect = new Rect(309, 310, 311, 312);
    public Object geometry_info;
    public Object rrd;
    // Deliberately preserve the IEEE-754 sign bit through the real encoder.
    public double m_factor_resize = -0.0d;

    public GoldenTrailRecord() {
        flag_penup = 101;
        flag_special = 102;
        font_height = 103;
        font_width = 104;
        layer_num = 7;
        m_after_shift_angle = 106;
        m_before_shift_angle = 107;
        m_copy = 108;
        m_draw_version = 109;
        m_emr_point_axis = 110;
        m_group_nest = 111;
        m_group_num = 112;
        m_mupdf_chapter = 113;
        m_mupdf_offset_x = -114;
        m_mupdf_offset_y = -115;
        m_mupdf_position = 116;
        m_redraw_height = 117;
        m_redraw_width = 118;
        m_rotate_angle = 119;
        m_trail_father = -121;
        m_trail_status = 123;
        m_trail_type = 124;
        max_x = 125;
        max_y = 126;
        page_num = 1;
        pre_num = 130;
        process_mod = 131;
        rec_mod = 132;
        recogn_trail_type = 133;
        trail_num = 17;
        walcom_emr_type = 135;
        m_trail_num_in_page = 19;
        m_thickness = 300;
        pen_type = 10;
        pen_color = 157;
        m_filter_flag = true;
        m_group_end = false;
        m_recogn_flag = true;
        m_render_flag = false;
        m_points.add(new Point(939, 388));
        m_points.add(new Point(1078, 401));
        pressures.add(100);
        pressures.add(200);
        angles.add(new GoldenAngle((short)11, (short)-12));
        angles.add(new GoldenAngle((short)13, (short)-14));
        flag_draw.add(true);
        flag_draw.add(false);
        flag_draw.add(true);
        timestamp.add(1788700000000L);
        timestamp.add(1788700000010L);
        disable_area_list.add(new GoldenFlagRect(
            201, -202, Integer.MAX_VALUE, Integer.MIN_VALUE, 205, -206));
        erase_line_trail_num.add(205);
        erase_line_trail_num.add(206);
        ArrayList<Object> contour = new ArrayList<Object>();
        contour.add(new PointF(-0.0f, 1.5f));
        contour.add(new PointF(Float.MIN_VALUE, -Float.MAX_VALUE));
        m_contours_src.add(contour);
        m_control_nums.add(Integer.MIN_VALUE);
        m_control_nums.add(Integer.MAX_VALUE);
        m_hierarchy.add("hierarchy-golden");
        m_mark_pen_d_fill_dir.add(new PointF(-0.0f, 0.0f));
        m_mark_pen_d_fill_dir.add(new PointF(1.5f, -2.25f));
        recogn_points.add(new GoldenRecognData(
            Integer.MIN_VALUE, Integer.MAX_VALUE, -211, Long.MIN_VALUE));
        recogn_points.add(new GoldenRecognData(212, -213, 214, Long.MAX_VALUE));
        geometry_info = new GoldenObject(401, "geometry-golden");
        rrd = new GoldenObject(402, "rrd-golden");
    }

    /** Mirrors the firmware's reflective two-field angle value. */
    public static final class GoldenAngle {
        public short x;
        public short y;

        GoldenAngle(short x, short y) {
            this.x = x;
            this.y = y;
        }
    }

    /** Mirrors the firmware's six-int JniFlagRect record exactly. */
    public static final class GoldenFlagRect {
        public int coorOrigin;
        public int flag;
        public int height;
        public int width;
        public int x;
        public int y;

        public GoldenFlagRect(int x, int y, int width, int height, int flag,
                int coorOrigin) {
            this.x = x;
            this.y = y;
            this.width = width;
            this.height = height;
            this.flag = flag;
            this.coorOrigin = coorOrigin;
        }
    }

    /** Mirrors JniRecognData, including its unusual capitalized field names. */
    public static final class GoldenRecognData {
        public int Flag;
        public int X;
        public int Y;
        public long timestamp;

        public GoldenRecognData(int x, int y, int flag, long timestamp) {
            this.X = x;
            this.Y = y;
            this.Flag = flag;
            this.timestamp = timestamp;
        }
    }

    /** Two distinct object-valued fields exercise recursive reflection. */
    public static final class GoldenObject {
        public int code;
        public String label;

        GoldenObject(int code, String label) {
            this.code = code;
            this.label = label;
        }
    }

    /** Ordinary native objects with these field names are unrepresentable in
     * evidence-v2 because the singleton wire objects are reserved for exact
     * IEEE-754 wrappers. They exist only as producer rejection vectors. */
    public static final class Binary32CollisionObject {
        public String binary32 = "ordinary-native-field";
    }

    public static final class Binary64CollisionObject {
        public String binary64 = "ordinary-native-field";
    }
}
