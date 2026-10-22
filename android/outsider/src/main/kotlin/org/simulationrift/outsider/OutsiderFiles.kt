package org.simulationrift.outsider

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/**
 * n7: one picture, readable by another app only through a grant, as a
 * gallery's provider serves it. Not exported; `grantUriPermissions` lets the
 * share intent carry a read grant for it.
 */
class OutsiderFiles : ContentProvider() {

    override fun onCreate() = true

    private fun picture(): File {
        val file = File(context!!.cacheDir, NAME)
        if (!file.exists()) {
            val image = Bitmap.createBitmap(300, 200, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.rgb(30, 160, 200)) }
            file.outputStream().use { image.compress(Bitmap.CompressFormat.PNG, 100, it) }
        }
        return file
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (uri.lastPathSegment != NAME || mode != "r") throw FileNotFoundException("$uri")
        return ParcelFileDescriptor.open(picture(), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, args: Array<out String>?, sort: String?): Cursor =
        MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)).apply { addRow(arrayOf(NAME, picture().length())) }

    override fun getType(uri: Uri) = "image/png"
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, args: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, args: Array<out String>?) = 0

    companion object {
        const val NAME = "rift-n7.png"
        val URI: Uri = Uri.parse("content://org.simulationrift.outsider.files/$NAME")
    }
}
