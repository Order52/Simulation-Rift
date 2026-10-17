package org.simulationrift.app;

/** Implemented by :browser so the controller can end it (§15 step 3). */
interface IBrowser {
    /** Finishes the browser activity; the process then exits on its own. */
    void shutdown();
}
