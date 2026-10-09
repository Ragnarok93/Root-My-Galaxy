package dev.busung.s25uroot

import java.util.concurrent.TimeUnit
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteProcessTimeoutTest {
    @Test
    fun alreadyFinishedReturnsTrueWithoutWaiting() {
        var ticks = 0
        val result = RemoteProcessTimeout.awaitExit(
            0, TimeUnit.MILLISECONDS,
            isAlive = { false },
            nowNanos = { 1L },
            pauseNanos = { ticks++ },
        )
        assertTrue(result)
        assertTrue(ticks == 0)
    }

    @Test
    fun longRunningProcessTimesOutWithoutQueryingExitValue() {
        var now = 0L
        var calls = 0
        val result = RemoteProcessTimeout.awaitExit(
            100, TimeUnit.MILLISECONDS,
            isAlive = { calls++; true },
            nowNanos = { now },
            pauseNanos = { delta -> now += delta },
        )
        assertFalse(result)
        assertTrue(calls >= 2)
        assertTrue(now >= TimeUnit.MILLISECONDS.toNanos(100))
    }

    @Test
    fun processThatFinishesBeforeDeadlineReturnsTrue() {
        var now = 0L
        var polls = 0
        val result = RemoteProcessTimeout.awaitExit(
            100, TimeUnit.MILLISECONDS,
            isAlive = { ++polls < 3 },
            nowNanos = { now },
            pauseNanos = { delta -> now += delta },
        )
        assertTrue(result)
        assertTrue(now < TimeUnit.MILLISECONDS.toNanos(100))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsNegativeTimeout() {
        RemoteProcessTimeout.awaitExit(
            -1, TimeUnit.MILLISECONDS,
            isAlive = { true },
            nowNanos = { 0L },
            pauseNanos = {},
        )
    }
}
