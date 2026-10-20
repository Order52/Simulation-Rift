package org.simulationrift.app

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File
import java.io.IOException
import java.io.InputStream

/**
 * Offline import of a threat-database update (§13.2): copies a TUF
 * repository the user chose into Rift's own storage, so that rift-update
 * verifies it with its file transport, the same code path as every update.
 *
 * Nothing here trusts the repository. Only `metadata/` and `targets/` are
 * read, only plain files whose names are a single plain component, within
 * a count and size bound; anything else is skipped and counted. tough then
 * checks every byte it uses against the trusted root, and rift-update reads
 * only the fixed pack files (Phase 0 finding, X2).
 */
internal object IntelImport {
    /** A repository directory: its two subdirectories, listed one level deep. */
    interface Tree {
        /** The entries of `dir` ("metadata" or "targets"); null if there is no such directory. */
        fun list(dir: String): List<Entry>?

        fun open(entry: Entry): InputStream
    }

    /** `handle` is the tree's own reference to the entry; only [Tree.open] interprets it. */
    data class Entry(val name: String, val isFile: Boolean, val handle: String)

    class Refused(message: String) : Exception(message)

    data class Copied(val files: Int, val skipped: Int)

    /** Bounds on what is copied; tough's own limits (rift-update `LIMITS`) are lower for metadata. */
    data class Limits(
        val entriesPerDirectory: Int = 64,
        val metadataBytes: Long = 1L * 1024 * 1024,
        val targetBytes: Long = 64L * 1024 * 1024,
        val totalBytes: Long = 160L * 1024 * 1024,
    )

    private val PLAIN_NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,159}")

    /**
     * Replaces `target` with the repository's plain files. Throws [Refused]
     * if a directory is missing or a bound is exceeded, and [IOException] if
     * reading or writing fails; `target` is then removed.
     */
    fun copy(tree: Tree, target: File, limits: Limits = Limits()): Copied {
        target.deleteRecursively()
        var files = 0
        var skipped = 0
        var total = 0L
        try {
            for (dir in listOf("metadata", "targets")) {
                val entries = tree.list(dir) ?: throw Refused("the folder has no $dir directory; choose the repository folder itself")
                if (entries.size > limits.entriesPerDirectory) {
                    throw Refused("$dir has ${entries.size} entries, more than an update may have (${limits.entriesPerDirectory})")
                }
                val out = File(target, dir).apply { mkdirs() }
                val limit = if (dir == "metadata") limits.metadataBytes else limits.targetBytes
                for (entry in entries) {
                    // ".." and "." fail the pattern; separators cannot occur in it.
                    if (!entry.isFile || !PLAIN_NAME.matches(entry.name) || entry.name.contains("..")) {
                        skipped++
                        continue
                    }
                    val budget = minOf(limit, limits.totalBytes - total)
                    total += tree.open(entry).use { input ->
                        File(out, entry.name).outputStream().use { output -> copyBounded(input, output, budget, "$dir/${entry.name}") }
                    }
                    files++
                }
            }
        } catch (e: Exception) {
            target.deleteRecursively()
            throw e
        }
        return Copied(files, skipped)
    }

    private fun copyBounded(input: InputStream, output: java.io.OutputStream, budget: Long, name: String): Long {
        val buffer = ByteArray(64 * 1024)
        var copied = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) return copied
            copied += n
            if (copied > budget) throw Refused("$name is larger than an update may be")
            output.write(buffer, 0, n)
        }
    }

    /** A directory on disk (tests, and the debug demo copy). */
    class FileTree(private val root: File) : Tree {
        override fun list(dir: String): List<Entry>? =
            File(root, dir).takeIf { it.isDirectory }?.listFiles()?.map { Entry(it.name, it.isFile, it.path) }

        override fun open(entry: Entry): InputStream = File(entry.handle).inputStream()
    }

    /** A folder the user chose in the system picker (`ACTION_OPEN_DOCUMENT_TREE`). */
    class DocumentTree(private val context: Context, private val tree: Uri) : Tree {
        override fun list(dir: String): List<Entry>? {
            val child = children(DocumentsContract.getTreeDocumentId(tree)).firstOrNull { it.name == dir && !it.isFile } ?: return null
            return children(child.handle)
        }

        override fun open(entry: Entry): InputStream =
            context.contentResolver.openInputStream(DocumentsContract.buildDocumentUriUsingTree(tree, entry.handle))
                ?: throw IOException("the document provider returned no data for ${entry.name}")

        private fun children(documentId: String): List<Entry> {
            val uri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, documentId)
            val columns = arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
            )
            val cursor = context.contentResolver.query(uri, columns, null, null, null)
                ?: throw IOException("the document provider did not list the folder")
            return cursor.use {
                buildList {
                    while (it.moveToNext()) {
                        // A missing name fails the name check and is counted as skipped.
                        val name = it.getString(1).orEmpty()
                        add(Entry(name, it.getString(2) != DocumentsContract.Document.MIME_TYPE_DIR, it.getString(0)))
                    }
                }
            }
        }
    }
}
