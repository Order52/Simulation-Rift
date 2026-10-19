package org.simulationrift.poc;

/** The browser app's session service, bound by the controller (signature permission). */
interface ISession {
    /** "uid=<n> pid=<n> process=<name> started=<elapsedRealtime>" */
    String hello();
    /** Every file and directory under the browser's data directories. */
    List<String> inventory();
    /** ActivityManager.clearApplicationUserData() on the browser itself. */
    boolean wipe();
}
