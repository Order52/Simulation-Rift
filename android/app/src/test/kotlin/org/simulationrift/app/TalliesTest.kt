package org.simulationrift.app

import org.junit.Assert.assertEquals
import org.junit.Test

class TalliesTest {
    private val today = 20_000L

    @Test
    fun countsRoundTripThroughTheFile() {
        // An earlier day comes from the file: counting is always for today.
        val (tallies, _) = Tallies.parse("${Tallies.HEADER}\n${today - 2} 0 0 1 0 0\n", today)
        repeat(3) { tallies.add(today, Tally.BLOCKED) }
        tallies.add(today, Tally.LINK_CHECKED)
        val (read, bad) = Tallies.parse(tallies.serialize(), today)
        assertEquals(0, bad)
        assertEquals(tallies.week(today), read.week(today))
        val week = read.week(today)
        assertEquals(3, week.total(Tally.BLOCKED))
        assertEquals(1, week.total(Tally.FLAGGED_FILE))
        assertEquals(today, week.days.last().epochDay)
        assertEquals(7, week.days.size)
    }

    @Test
    fun onlyTheKeptWindowSurvives() {
        val tallies = Tallies()
        tallies.add(today - 20, Tally.BLOCKED)
        tallies.add(today, Tally.BLOCKED)
        // A clock set back: the days it puts in the future are dropped.
        tallies.add(today - 30, Tally.WARNED)
        assertEquals(0, tallies.week(today).total(Tally.BLOCKED))
        assertEquals("${Tallies.HEADER}\n${today - 30} 0 1 0 0 0\n", tallies.serialize())
    }

    @Test
    fun damagedLinesAreSkippedAndCounted() {
        val text = "${Tallies.HEADER}\n$today 1 2 3 4 5\nnot a line\n${today - 1} -4 1\n${today - 2} 7\n${today - 3} 1 1 1 1 1 9\n"
        val (read, bad) = Tallies.parse(text, today)
        assertEquals(2, bad)
        val week = read.week(today)
        // A short line (older file) reads as zeros; an extra column is ignored.
        assertEquals(1 + 7 + 1, week.total(Tally.BLOCKED))
        assertEquals(5 + 1, week.total(Tally.FILE_SCANNED))
    }

    @Test
    fun anUnknownFormatIsNotRead() {
        val (read, bad) = Tallies.parse("rift-stats 9\n$today 1 1 1 1 1\n", today)
        assertEquals(2, bad)
        assertEquals(0, read.week(today).total(Tally.BLOCKED))
    }

    @Test
    fun countsSaturate() {
        val (read, _) = Tallies.parse("${Tallies.HEADER}\n$today ${Long.MAX_VALUE} 0 0 0 0\n${today - 1} ${Int.MAX_VALUE} 0 0 0 0\n", today)
        read.add(today, Tally.BLOCKED)
        assertEquals(Int.MAX_VALUE, read.week(today).total(Tally.BLOCKED))
    }

    @Test
    fun mergeAddsAFileReadAfterCountingBegan() {
        val counting = Tallies()
        counting.add(today, Tally.WARNED)
        val (read, _) = Tallies.parse("${Tallies.HEADER}\n$today 0 2 0 0 0\n", today)
        counting.merge(read, today)
        assertEquals(3, counting.week(today).total(Tally.WARNED))
    }
}
