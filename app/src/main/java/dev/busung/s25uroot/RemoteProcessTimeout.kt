package dev.busung.s25uroot

import java.util.concurrent.TimeUnit

/**
 * Bounded polling for remote shell processes. The Shizuku remote process
 * does not implement java.lang.Process's exitValue() exception contract:
 * asking for an exit code while a command is running raises
 * IllegalArgumentException instead of IllegalThreadStateException.
 *
 * This helper deliberately polls only the remote alive state and remains
 * independent of Android APIs so timeout handling can be regression-tested.
 */
internal object RemoteProcessTimeout {
    private val POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(40)

    fun awaitExit(timeout: Long, unit: TimeUnit, isAlive: () -> Boolean): Boolean =
        awaitExit(
            timeout = timeout,
            unit = unit,
            isAlive = isAlive,
            nowNanos = System::nanoTime,
            pauseNanos = { TimeUnit.NANOSECONDS.sleep(it) },
        )

    internal fun awaitExit(
        timeout: Long,
        unit: TimeUnit,
        isAlive: () -> Boolean,
        nowNanos: () -> Long,
        pauseNanos: (Long) -> Unit,
    ): Boolean {
        require(timeout >= 0) { "Timeout must be nonnegative" }
        val timeoutNanos = unit.toNanos(timeout)
        val start = nowNanos()
        while (true) {
            if (!isAlive()) return true
            val elapsed = nowNanos() - start
            val remaining = timeoutNanos - elapsed
            if (remaining <= 0L) return false
            pauseNanos(minOf(remaining, POLL_NANOS))
        }
    }
}
