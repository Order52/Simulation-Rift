package org.simulationrift.bridge;

/** Implemented by the browser's `:web` process so the controller can end it (§15 step 3). */
interface IBrowser {
    /** Finishes the browser activity; the system wipe that follows kills the process. */
    void shutdown();
}
