package com.techrebbe.supernote.disposableleasehost;

/** Independent synthetic authorities; toggling one never changes the others. */
public final class ProbeModel {
    private int page = 1;
    private boolean alternateUri;
    private long renderEpoch;
    private long layoutEpoch;

    public boolean apply(String command) {
        if ("page".equals(command)) {
            page = page == 1 ? 2 : 1;
        } else if ("uri".equals(command)) {
            alternateUri = !alternateUri;
        } else if ("render".equals(command)) {
            renderEpoch++;
        } else if ("layout".equals(command)) {
            layoutEpoch++;
        } else {
            return false;
        }
        return true;
    }

    public int page() { return page; }
    public String uri() {
        return alternateUri ? "probe://disposable-host/source-b"
                : "probe://disposable-host/source-a";
    }
    public long renderEpoch() { return renderEpoch; }
    public long layoutEpoch() { return layoutEpoch; }
    public boolean alternateLayout() { return (layoutEpoch & 1L) != 0L; }
}
