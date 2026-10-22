package org.simulationrift.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** The wipe request's retry (AndroidBrowserDisposal.requestWipe), without Binder. */
class BrowserDisposalTest {
    private class Instance(val answer: Boolean?) : AutoCloseable {
        var closed = false
        override fun close() {
            closed = true
        }
    }

    private fun run(vararg answers: Boolean?, attempts: Int = 2): Triple<Pair<Instance, Boolean>?, List<Instance>, List<Int>> {
        val made = mutableListOf<Instance>()
        val died = mutableListOf<Int>()
        val queue = ArrayDeque(answers.toList())
        val result = firstAnswer(attempts, next = { Instance(queue.removeFirst()).also { made += it } }, ask = { it.answer }, onDied = { died += it })
        return Triple(result, made, died)
    }

    @Test
    fun theFirstInstanceThatAnswersIsKeptOpen() {
        val (result, made, died) = run(true)
        assertSame(made.single(), result!!.first)
        assertTrue(result.second)
        assertFalse(made.single().closed)
        assertEquals(emptyList<Int>(), died)
    }

    @Test
    fun anInstanceThatDiedFirstIsClosedAndAnotherAsked() {
        val (result, made, died) = run(null, true)
        assertEquals(2, made.size)
        assertTrue(made[0].closed)
        assertSame(made[1], result!!.first)
        assertFalse(made[1].closed)
        assertEquals(listOf(1), died)
    }

    @Test
    fun aRefusalIsAnAnswer() {
        // Not retried: the caller fails the reset on it.
        val (result, made, _) = run(false, true)
        assertEquals(1, made.size)
        assertFalse(result!!.second)
    }

    @Test
    fun theAttemptsAreBounded() {
        val (result, made, died) = run(null, null, null)
        assertNull(result)
        assertEquals(2, made.size)
        assertTrue(made.all { it.closed })
        assertEquals(listOf(1, 2), died)
    }

    @Test
    fun anInstanceIsClosedWhenAskingThrows() {
        val made = mutableListOf<Instance>()
        assertThrows(IllegalStateException::class.java) {
            firstAnswer(2, next = { Instance(true).also { made += it } }, ask = { throw IllegalStateException("broken") })
        }
        assertTrue(made.single().closed)
    }
}
