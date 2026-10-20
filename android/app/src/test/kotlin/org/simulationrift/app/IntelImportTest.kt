package org.simulationrift.app

import java.io.File
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class IntelImportTest {
    private val work: File = Files.createTempDirectory("rift-import").toFile()
    private val source = File(work, "chosen")
    private val target = File(work, "copy")

    @After
    fun cleanUp() {
        work.deleteRecursively()
    }

    private fun write(path: String, bytes: Int = 4) = File(source, path).apply {
        parentFile.mkdirs()
        writeBytes(ByteArray(bytes) { 'x'.code.toByte() })
    }

    private fun repository() {
        write("metadata/1.root.json")
        write("metadata/timestamp.json")
        write("metadata/3.snapshot.json")
        write("metadata/3.targets.json")
        write("targets/2e5f.rules.yar")
        write("targets/4dda.file-hashes.bin")
    }

    private fun copied(): List<String> =
        target.walkTopDown().filter { it.isFile }.map { it.relativeTo(target).path }.sorted().toList()

    @Test
    fun copiesOnlyPlainFilesOfTheTwoDirectories() {
        repository()
        write("README.md") // outside metadata/ and targets/
        write("targets/.hidden")
        write("targets/name with space")
        write("targets/a..b")
        write("targets/sub/inner.json") // a subdirectory is not followed
        val result = IntelImport.copy(IntelImport.FileTree(source), target)
        assertEquals(IntelImport.Copied(files = 6, skipped = 4), result)
        assertEquals(
            listOf(
                "metadata/1.root.json", "metadata/3.snapshot.json", "metadata/3.targets.json", "metadata/timestamp.json",
                "targets/2e5f.rules.yar", "targets/4dda.file-hashes.bin",
            ),
            copied(),
        )
    }

    @Test
    fun hostileEntryNamesNeverLeaveTheCopy() {
        repository()
        // A tree can report any name, whatever the disk allows.
        val tree = object : IntelImport.Tree {
            val plain = IntelImport.FileTree(source)
            override fun list(dir: String) = plain.list(dir)?.plus(
                listOf("../escape", "/abs", "..", ".", "targets/../../x", "a\\b", "", "é.json").map { IntelImport.Entry(it, true, "unused") },
            )

            override fun open(entry: IntelImport.Entry) =
                if (entry.handle == "unused") throw AssertionError("opened ${entry.name}") else plain.open(entry)
        }
        val result = IntelImport.copy(tree, target)
        assertEquals(6, result.files)
        assertEquals(16, result.skipped) // eight per directory
        assertFalse(File(work, "escape").exists())
        assertTrue(copied().all { it.startsWith("metadata/") || it.startsWith("targets/") })
    }

    @Test
    fun aMissingDirectoryIsRefused() {
        write("metadata/1.root.json")
        assertRefused("no targets directory") { IntelImport.copy(IntelImport.FileTree(source), target) }
        assertFalse("a refused copy is removed", target.exists())
    }

    @Test
    fun oversizedFilesAreRefusedWhileCopying() {
        repository()
        write("targets/big.bin", bytes = 101)
        val limits = IntelImport.Limits(targetBytes = 100)
        assertRefused("targets/big.bin is larger") { IntelImport.copy(IntelImport.FileTree(source), target, limits) }
        assertFalse(target.exists())
    }

    @Test
    fun theTotalSizeIsBounded() {
        repository() // 6 files of 4 bytes
        val limits = IntelImport.Limits(totalBytes = 20)
        assertRefused("larger than an update may be") { IntelImport.copy(IntelImport.FileTree(source), target, limits) }
    }

    @Test
    fun tooManyEntriesAreRefused() {
        repository()
        repeat(5) { write("targets/extra$it") }
        val limits = IntelImport.Limits(entriesPerDirectory = 6)
        assertRefused("targets has 7 entries") { IntelImport.copy(IntelImport.FileTree(source), target, limits) }
    }

    @Test
    fun anEarlierCopyIsReplaced() {
        repository()
        File(target, "metadata/stale.json").apply { parentFile.mkdirs(); writeText("old") }
        IntelImport.copy(IntelImport.FileTree(source), target)
        assertFalse(File(target, "metadata/stale.json").exists())
    }

    private fun assertRefused(expected: String, block: () -> Unit) {
        try {
            block()
            fail("not refused")
        } catch (e: IntelImport.Refused) {
            assertTrue("${e.message}", e.message!!.contains(expected))
        }
    }
}
