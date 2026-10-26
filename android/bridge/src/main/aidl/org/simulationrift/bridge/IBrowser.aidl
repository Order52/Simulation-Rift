package org.simulationrift.bridge;

/** Implemented by the browser's `:web` process so the controller can end it (§15 step 3). */
interface IBrowser {
    /**
     * Finishes the browser activity; the system wipe that follows kills the
     * process. Two-way, so the activity is gone before the wipe: finishing it
     * during the wipe removes its task while Android restarts the app, which
     * on API 34 left a process record that never started. The controller
     * bounds the wait (AndroidBrowserDisposal).
     */
    void shutdown();
}
