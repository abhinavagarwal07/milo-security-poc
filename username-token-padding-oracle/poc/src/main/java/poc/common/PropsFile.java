package poc.common;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Properties;

/**
 * Tiny key=value file helper used for every inter-process handoff in this PoC
 * (server-info.properties, capture.properties, checkpoint.properties, recovered.properties).
 *
 * Deliberately not JSON -- no extra dependency, human-readable, trivial to grep/audit. Writes are
 * atomic (write to a temp file in the same directory, then rename) so a reader never sees a
 * partially-written file.
 */
public final class PropsFile {

  private PropsFile() {}

  public static Properties load(Path path) {
    Properties p = new Properties();
    try (FileInputStream in = new FileInputStream(path.toFile())) {
      p.load(in);
    } catch (IOException e) {
      throw new RuntimeException("failed to read " + path, e);
    }
    return p;
  }

  public static boolean exists(Path path) {
    return Files.exists(path);
  }

  public static void store(Path path, Properties props, String comment) {
    try {
      Path dir = path.toAbsolutePath().getParent();
      Path tmp = Files.createTempFile(dir, path.getFileName().toString(), ".tmp");
      try (FileOutputStream out = new FileOutputStream(tmp.toFile())) {
        props.store(out, comment);
      }
      Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    } catch (IOException e) {
      throw new RuntimeException("failed to write " + path, e);
    }
  }
}
