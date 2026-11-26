package com.tenzro.node

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NodeArgsTest {
    @Test
    fun theNodeRunsAsALightNodeInTheAppsDirectoryWithTheOperatorsArguments() {
        assertArrayEquals(
            arrayOf("--data-dir", "/data/files/node", "--roles", "light", "--boot-nodes", "did:tenzro:machine:x"),
            NodeArgs.of("/data/files/node", arrayOf("--boot-nodes", "did:tenzro:machine:x")),
        )
    }

    @Test
    fun theOperatorCannotMoveTheDataDirectoryOrChangeTheRoles() {
        for (extra in listOf(
            arrayOf("--data-dir", "/sdcard"),
            arrayOf("--data-dir=/sdcard"),
            arrayOf("--roles", "validator"),
            arrayOf("--roles=validator"),
            arrayOf("a\u0000b"),
        )) {
            assertThrows(IllegalArgumentException::class.java) { NodeArgs.of("/d", extra) }
        }
    }

    @Test
    fun storedArgumentsReadBackAsTheyWere() {
        val args = arrayOf("--boot-nodes", "did:tenzro:machine:a,did:tenzro:machine:b", "--rpc-addr", "127.0.0.1:8545")
        assertEquals(args.toList(), NodeArgs.join(args).split('\u0000').filter { it.isNotEmpty() })
    }
}
