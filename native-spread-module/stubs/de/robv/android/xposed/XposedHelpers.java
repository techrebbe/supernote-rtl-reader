package de.robv.android.xposed;

public final class XposedHelpers {
    private XposedHelpers() {
    }

    public static XC_MethodHook.Unhook findAndHookMethod(
        String className,
        ClassLoader classLoader,
        String methodName,
        Object... parameterTypesAndCallback
    ) {
        return null;
    }

    public static Object getObjectField(Object object, String fieldName) {
        return null;
    }

    public static void setObjectField(
        Object object,
        String fieldName,
        Object value
    ) {
    }

    public static int getIntField(Object object, String fieldName) {
        return 0;
    }

    public static void setIntField(
        Object object,
        String fieldName,
        int value
    ) {
    }

    public static boolean getBooleanField(Object object, String fieldName) {
        return false;
    }

    public static void setBooleanField(
        Object object,
        String fieldName,
        boolean value
    ) {
    }

    public static Object callMethod(Object object, String methodName, Object... args) {
        return null;
    }
}
