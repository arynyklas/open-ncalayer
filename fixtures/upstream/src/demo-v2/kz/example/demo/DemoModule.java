// Synthetic fixture of the OpenNCALayer upstream watcher (Apache-2.0).
package kz.example.demo;

import kz.example.annotations.NCALayerMethod;

/** A module with two methods for pages. */
public class DemoModule {
    public static final String MODULE = "kz.example.demo.DemoModule";
    public static final String SIGN_ERROR = "SIGN_ERROR";
    public static final String VERIFY_FAILED = "VERIFY_FAILED";
    public static final String TSP_URL = "http://tsp.example.invalid/";
    public static final int PORT = 13579;
    protected int calls;
    private String last;

    @NCALayerMethod
    public String sign(String data) {
        calls++;
        last = data;
        if (data == null) {
            return SIGN_ERROR;
        }
        return data + TSP_URL;
    }

    @NCALayerMethod
    public String verify(String data) {
        return data == null ? VERIFY_FAILED : data;
    }

    String packageHelper() {
        return last;
    }

    private void privateHelper() {
        last = null;
    }

    protected int calls() {
        return calls;
    }
}
