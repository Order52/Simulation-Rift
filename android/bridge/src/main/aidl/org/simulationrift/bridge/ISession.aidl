package org.simulationrift.bridge;

/**
 * The browser app's session service (§15 steps 3–4), in its default
 * process, which never loads WebView. Only the controller may bind it.
 */
interface ISession {
    /** This process's id, so the controller can tell a fresh instance from the old one. */
    int pid();

    /**
     * Every file under the browser app's data directories, as relative
     * paths. Directories are not listed: the platform recreates some empty.
     */
    List<String> inventory();

    /**
     * ActivityManager.clearApplicationUserData() on the browser app itself:
     * the system kills every process of the package and deletes all its
     * data. The call usually does not return, because this process dies.
     */
    boolean wipe();
}
