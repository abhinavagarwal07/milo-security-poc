package poc.common;

import java.util.HashMap;
import java.util.Map;

/** Minimal {@code --flag value} CLI argument parser shared by every process's main(). */
public final class Args {

  private final Map<String, String> values = new HashMap<>();
  private final java.util.Set<String> flags = new java.util.HashSet<>();

  public static Args parse(String[] argv) {
    Args a = new Args();
    int i = 0;
    while (i < argv.length) {
      String arg = argv[i];
      if (!arg.startsWith("--")) {
        throw new IllegalArgumentException("expected --flag, got: " + arg);
      }
      String name = arg.substring(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        a.values.put(name, argv[i + 1]);
        i += 2;
      } else {
        a.flags.add(name);
        i += 1;
      }
    }
    return a;
  }

  public String get(String name) {
    return values.get(name);
  }

  public String get(String name, String defaultValue) {
    return values.getOrDefault(name, defaultValue);
  }

  public String require(String name) {
    String v = values.get(name);
    if (v == null) {
      throw new IllegalArgumentException("missing required --" + name);
    }
    return v;
  }

  public int getInt(String name, int defaultValue) {
    String v = values.get(name);
    return v == null ? defaultValue : Integer.parseInt(v);
  }

  public long getLong(String name, long defaultValue) {
    String v = values.get(name);
    return v == null ? defaultValue : Long.parseLong(v);
  }

  public boolean has(String flagName) {
    return flags.contains(flagName) || values.containsKey(flagName);
  }
}
