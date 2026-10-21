package org.simulationrift.outsider

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.autofill.AutofillId

/**
 * h3: an autofill service, as a password manager is. It fills nothing and
 * logs which app each request came from and what it was told; the test
 * reads the log. Rift's windows must tell it nothing of their content.
 */
class OutsiderAutofill : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val context = request.fillContexts.lastOrNull()
        val from = context?.structure?.activityComponent?.packageName
        // What the service learnt: the focused field, and every web domain,
        // text and hint in the structure it was given.
        val focused = context?.let { find(it.structure, it.focusedId) }
        val learnt = context?.let { learnt(it.structure) }.orEmpty()
        Log.i(TAG, "fill request from $from (focused ${focused?.className}; learnt ${learnt.size}: ${learnt.take(8).joinToString(" | ")})")
        callback.onSuccess(null)
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val from = request.fillContexts.lastOrNull()?.structure?.activityComponent?.packageName
        Log.i(TAG, "save request from $from")
        callback.onSuccess()
    }

    private fun learnt(structure: AssistStructure): List<String> {
        val found = ArrayList<String>()
        fun walk(node: AssistStructure.ViewNode) {
            node.webDomain?.let { found.add("domain $it") }
            node.text?.takeIf { it.isNotBlank() }?.let { found.add("text $it") }
            node.hint?.takeIf { it.isNotBlank() }?.let { found.add("hint $it") }
            node.autofillHints?.forEach { found.add("autofill hint $it") }
            for (i in 0 until node.childCount) walk(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)
        return found
    }

    private fun find(structure: AssistStructure, id: AutofillId): AssistStructure.ViewNode? {
        fun walk(node: AssistStructure.ViewNode): AssistStructure.ViewNode? {
            if (node.autofillId == id) return node
            for (i in 0 until node.childCount) walk(node.getChildAt(i))?.let { return it }
            return null
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)?.let { return it }
        return null
    }

    private companion object {
        const val TAG = "rift-outsider-autofill"
    }
}
