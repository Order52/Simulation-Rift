package org.simulationrift.outsider

import android.accessibilityservice.AccessibilityService
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * h4: an accessibility service that is not a tool for users with
 * disabilities, as screen-reading malware is. For each window it is told
 * about it logs the package and the texts it can read; the host step
 * reads the log. In Rift's windows it must read nothing (API 34+).
 */
class OutsiderAccessibility : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val root = rootInActiveWindow ?: return
        val texts = ArrayList<String>()
        collect(root, texts)
        Log.i(TAG, "window ${root.packageName}: ${texts.size} texts: ${texts.take(MAX_LOGGED).joinToString(" | ")}")
    }

    private fun collect(node: AccessibilityNodeInfo, into: MutableList<String>) {
        if (into.size >= MAX_TEXTS) return
        node.text?.takeIf { it.isNotBlank() }?.let { into.add(it.toString().take(40)) }
        for (i in 0 until node.childCount) node.getChild(i)?.let { collect(it, into) }
    }

    override fun onInterrupt() = Unit

    private companion object {
        const val TAG = "rift-outsider-a11y"
        const val MAX_TEXTS = 200
        const val MAX_LOGGED = 6
    }
}
