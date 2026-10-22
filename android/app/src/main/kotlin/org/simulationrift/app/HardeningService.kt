package org.simulationrift.app

import android.content.Context
import android.os.Binder
import android.os.Parcel
import android.os.Process
import java.io.IOException
import java.util.concurrent.TimeUnit
import org.simulationrift.bridge.Rift

/**
 * Rift's privileged helper (§8.9). Shizuku or Sui runs it in a process of
 * its own, as shell or root, only while the user has extra isolation on;
 * Rift's app process never has these rights. It answers Rift's controller
 * only, and runs fixed Android tools with fixed arguments: the browser's
 * package name and two numbers it checks. Nothing is passed to a shell.
 */
class HardeningService(context: Context?) : IHardening.Stub() {

    /** Shizuku before 13 passes no Context; then no caller can be checked, so every call is refused. */
    constructor() : this(null)

    /** The controller's UID, the only caller answered. */
    private val controller: Int? = context?.applicationInfo?.uid

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        val caller = Binder.getCallingUid()
        // Shizuku (same UID as this process) ends the helper when Rift unbinds
        // or dies. It sends no interface token, which the generated stub would
        // refuse, so the call is answered here.
        if (code == DESTROY && (caller == Process.myUid() || caller == controller)) {
            destroy()
            return true
        }
        if (caller != controller) throw SecurityException("Rift's helper answers Rift only")
        return super.onTransact(code, data, reply, flags)
    }

    override fun uid(): Int = Process.myUid()

    override fun blockClipboard(blocked: Boolean): String? {
        // Undone with "allow", these ops' own default: "default" would store
        // MODE_DEFAULT, which the clipboard service refuses as well.
        val mode = if (blocked) "ignore" else "allow"
        for (op in CLIPBOARD_OPS) {
            val now = run("cmd", "appops", "get", "--user", user(), Rift.BROWSER_PACKAGE, op)
            if (now.code == 0 && ignores(now.output, op) == blocked) continue
            run("cmd", "appops", "set", "--user", user(), Rift.BROWSER_PACKAGE, op, mode).problem("setting $op")?.let { return it }
            val read = run("cmd", "appops", "get", "--user", user(), Rift.BROWSER_PACKAGE, op)
            if (read.code != 0 || ignores(read.output, op) != blocked) return "$op reads back as \"${read.output.take(MAX_OUTPUT)}\""
        }
        return null
    }

    override fun clearBrowser(): String? {
        val result = run("pm", "clear", "--user", user(), Rift.BROWSER_PACKAGE)
        return if (result.code == 0 && result.output.contains("Success")) null else "pm clear: ${result.output.take(MAX_OUTPUT)}"
    }

    /*
     * The rules, in the form `iptables -S` prints them, so they can be read
     * back exactly. Loopback is open to the proxy's port only. With the
     * network lock on, anything routed into a VPN goes on to it (the lock,
     * whose drops are listed); with it off, a VPN may be the user's own,
     * which would carry the browser past the proxy, so nothing goes there.
     * Everything else is refused, so the browser stays off the network even
     * if the VPN is gone.
     */
    private fun ipv4Rules(port: Int, intoVpn: Boolean) = listOfNotNull(
        "-d 127.0.0.1/32 -o lo -p tcp -m tcp --dport $port -j RETURN",
        "-o tun+ -j RETURN".takeIf { intoVpn },
        "-p tcp -j REJECT --reject-with tcp-reset",
        "-j REJECT --reject-with icmp-port-unreachable",
    )

    private fun ipv6Rules(intoVpn: Boolean) = listOfNotNull(
        "-o tun+ -j RETURN".takeIf { intoVpn },
        "-p tcp -j REJECT --reject-with tcp-reset",
        "-j REJECT --reject-with icmp6-port-unreachable",
    )

    override fun lockNetwork(browserUid: Int, proxyPort: Int, intoVpn: Boolean): String? {
        if (Process.myUid() != 0) return "needs root"
        badUid(browserUid)?.let { return it }
        if (proxyPort !in 1024..65535) return "port $proxyPort is out of range"
        for ((tool, rules) in listOf("iptables" to ipv4Rules(proxyPort, intoVpn), "ip6tables" to ipv6Rules(intoVpn))) {
            val jump = jump(browserUid)
            if (inEffect(tool, rules, jump)) continue
            // Rewritten only as a session's browser registers: the browser
            // before it has been wiped, and this one loads nothing until
            // the controller answers, after this returns.
            if (run(tool, "-w", "-S", CHAIN).code != 0) run(tool, "-w", "-N", CHAIN).problem("$tool: creating $CHAIN")?.let { return it }
            run(tool, "-w", "-F", CHAIN).problem("$tool: flushing $CHAIN")?.let { return it }
            for (rule in rules) run(tool, "-w", "-A", CHAIN, *rule.split(' ').toTypedArray()).problem("$tool: $rule")?.let { return it }
            while (run(tool, "-w", "-C", "OUTPUT", *jump).code == 0) {
                run(tool, "-w", "-D", "OUTPUT", *jump).problem("$tool: moving the jump")?.let { return it }
            }
            run(tool, "-w", "-I", "OUTPUT", "1", *jump).problem("$tool: adding the jump")?.let { return it }
            if (!inEffect(tool, rules, jump)) return "$tool: the rules do not read back as written"
        }
        return null
    }

    override fun unlockNetwork(browserUid: Int): String? {
        if (Process.myUid() != 0) return "needs root"
        badUid(browserUid)?.let { return it }
        for (tool in listOf("iptables", "ip6tables")) {
            while (run(tool, "-w", "-C", "OUTPUT", *jump(browserUid)).code == 0) {
                run(tool, "-w", "-D", "OUTPUT", *jump(browserUid)).problem("$tool: removing the jump")?.let { return it }
            }
            if (run(tool, "-w", "-S", CHAIN).code != 0) continue
            run(tool, "-w", "-F", CHAIN).problem("$tool: flushing $CHAIN")?.let { return it }
            // Fails while another UID's jump (an earlier install's) still uses the chain; the chain is then empty.
            run(tool, "-w", "-X", CHAIN)
        }
        return null
    }

    override fun destroy() {
        System.exit(0)
    }

    /** The chain holds exactly `rules`, and the browser UID's jump to it is OUTPUT's first rule. */
    private fun inEffect(tool: String, rules: List<String>, jump: Array<String>): Boolean {
        val listed = run(tool, "-w", "-S", CHAIN)
        val first = run(tool, "-w", "-S", "OUTPUT", "1")
        return listed.code == 0 && listed.output.lines() == listOf("-N $CHAIN") + rules.map { "-A $CHAIN $it" } &&
            first.code == 0 && first.output == "-A OUTPUT ${jump.joinToString(" ")}"
    }

    private fun jump(uid: Int) = arrayOf("-m", "owner", "--uid-owner", uid.toString(), "-j", CHAIN)

    /** The browser's UID must be an app's, in the controller's user. */
    private fun badUid(uid: Int): String? {
        val caller = controller ?: return "no caller"
        return if (uid / PER_USER == caller / PER_USER && uid % PER_USER in APP_UIDS) null else "$uid is not an app in Rift's user"
    }

    private fun user(): String = ((controller ?: 0) / PER_USER).toString()

    private fun ignores(output: String, op: String) = output.lineSequence().any { it.trim().startsWith("$op: ignore") }

    private data class Result(val code: Int, val output: String) {
        fun problem(what: String): String? = if (code == 0) null else "$what failed ($code): ${output.take(MAX_OUTPUT)}"
    }

    private fun run(vararg argv: String): Result {
        if (controller == null) return Result(-1, "Shizuku 13 or later is needed")
        val process = try {
            ProcessBuilder(*argv).redirectErrorStream(true).start()
        } catch (e: IOException) {
            return Result(-1, "${argv[0]} could not run: ${e.message}")
        }
        process.outputStream.close()
        // Every command here prints a few lines at most, well under a pipe's buffer.
        if (!process.waitFor(COMMAND_TIMEOUT_S, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return Result(-1, "${argv[0]} did not finish")
        }
        return Result(process.exitValue(), process.inputStream.bufferedReader().use { it.readText() }.trim())
    }

    private companion object {
        const val CHAIN = "rift_browser"
        val CLIPBOARD_OPS = listOf("READ_CLIPBOARD", "WRITE_CLIPBOARD")
        const val DESTROY = 16777115
        const val PER_USER = 100_000
        val APP_UIDS = 10_000..19_999
        const val COMMAND_TIMEOUT_S = 10L
        const val MAX_OUTPUT = 300
    }
}
