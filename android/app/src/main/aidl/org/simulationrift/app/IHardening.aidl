package org.simulationrift.app;

/**
 * Extra isolation (§8.9): Rift's privileged helper, which Shizuku or Sui
 * runs as shell (uid 2000) or root (uid 0) when the user turns it on. Every
 * call acts on Rift's browser app only and answers Rift's controller only.
 * Each change is read back: a call returns null once the change is in
 * effect, or what went wrong.
 */
interface IHardening {
    /** 0 for root, 2000 for shell. */
    int uid() = 1;

    /** Has Android ignore the browser app's clipboard reads and writes, or stop ignoring them. */
    String blockClipboard(boolean blocked) = 2;

    /** Has Android clear the browser app's data, which stops every process of it. */
    String clearBrowser() = 3;

    /** Root only: the browser app's UID may connect to loopback port `proxyPort` and its VPN, nothing else. */
    String lockNetwork(int browserUid, int proxyPort) = 4;

    /** Root only: removes the rules of lockNetwork. */
    String unlockNetwork(int browserUid) = 5;

    /** Shizuku's code for ending the helper's process. */
    void destroy() = 16777114;
}
