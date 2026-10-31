// Synthetic fixture of the OpenNCALayer upstream watcher (Apache-2.0).
package kz.example.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Marks a method a page may call. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface NCALayerMethod {
}
