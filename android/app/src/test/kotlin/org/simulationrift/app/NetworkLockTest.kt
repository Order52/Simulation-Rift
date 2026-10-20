package org.simulationrift.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Which dropped packets the page watch (§10.5) reports as connection attempts. */
class NetworkLockTest {
    @Test
    fun systemBackgroundTrafficIsNotAnAttempt() {
        for (destination in listOf(
            "ICMPv6 [ff02::2]",
            "ICMP 10.0.2.2",
            "protocol 0 [ff02::16]",
            "UDP [ff02::fb]:5353",
            "UDP 224.0.0.251:5353",
            "UDP 255.255.255.255:67",
            "UDP 10.111.0.2:53",
            "TCP 10.111.0.2:853",
        )) {
            assertTrue(destination, NetworkLock.isBackground(destination))
        }
    }

    @Test
    fun connectionsAroundTheProxyAreAttempts() {
        for (destination in listOf(
            "UDP 10.0.2.2:3478",
            "TCP 1.1.1.1:443",
            "TCP 10.111.0.2:443",
            "UDP 8.8.8.8:53",
            "TCP [2001:db8::1]:443",
            "UDP [fe80::1]:3478",
            "protocol 47 10.0.2.2",
        )) {
            assertFalse(destination, NetworkLock.isBackground(destination))
        }
    }
}
