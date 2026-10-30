// Synthetic fixture of the OpenNCALayer upstream watcher (Apache-2.0).
package kz.example.demo;

/** Starts the module. */
public class Activator {
    public void start(Object context) {
        new DemoModule();
    }

    public void stop(Object context) {
    }
}
