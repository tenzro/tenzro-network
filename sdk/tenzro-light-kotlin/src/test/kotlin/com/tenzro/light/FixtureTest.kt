package com.tenzro.light

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import org.json.JSONArray
import org.json.JSONObject

/** Replays the shared fixture: the node's replies the Rust core recorded. */
class Replay(private val calls: JSONArray) : Transport {
    override fun call(method: String, paramsJson: String): String {
        for (i in 0 until calls.length()) {
            val c = calls.getJSONObject(i)
            if (c.getString("method") == method && c.getString("params") == paramsJson) {
                return c.getString("result")
            }
        }
        throw TransportException.Failed("no recorded reply to $method $paramsJson")
    }
}

class FixtureTest {
    private val fixture = JSONObject(File(System.getProperty("tenzro.fixture")).readText())
    private val expect = fixture.getJSONObject("expect")
    private val transport = Replay(fixture.getJSONArray("calls"))
    private val clock = fixture.getJSONObject("clock").let {
        Clock(
            nowMs = it.getLong("now_ms").toULong(),
            maxAgeMs = it.getLong("max_age_ms").toULong(),
            maxAheadMs = it.getLong("max_ahead_ms").toULong(),
        )
    }

    private fun client() = LightClient(
        fixture.getLong("chain_id").toULong(),
        fixture.getString("genesis_hash"),
        fixture.getLong("epoch").toULong(),
        fixture.getString("committee_root"),
        fixture.getString("committee_reply"),
    )

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test
    fun syncsAndProvesAnIdentitysKeys() {
        val lc = client()
        val cp = lc.sync(transport, clock)
        val want = expect.getJSONObject("checkpoint")
        assertEquals(want.getLong("index").toULong(), cp.index)
        assertEquals(want.getString("state_root"), cp.stateRoot.hex())

        val id = expect.getJSONObject("identity")
        val proven = lc.resolveIdentity(transport, id.getString("did"), clock)!!
        assertEquals(id.getString("controller_key"), proven.controllerKey.hex())
        assertEquals(id.getString("ml_dsa_key"), proven.mlDsaKey.hex())
        assertEquals(id.getString("key_digest"), proven.keyDigest.hex())
        assertEquals(id.getBoolean("revoked"), proven.revoked)

        assertNull(lc.resolveIdentity(transport, expect.getString("absent_did"), clock))
    }

    @Test
    fun provesAnIdentitysKeyHistory() {
        val lc = client()
        val cp = lc.sync(transport, clock)
        val want = expect.getJSONObject("key_history")
        val history = lc.keyHistory(transport, expect.getJSONObject("identity").getString("did"), clock)
        assertEquals(want.getInt("keys"), history.epochs().size)
        assertEquals(want.getLong("sequence").toULong(), history.sequence())
        assertEquals(want.getString("head"), history.head().hex())
        val key = history.keyAt(cp.timestampMs)!!
        assertEquals(want.getLong("version").toULong(), key.version)
        assertEquals(want.getString("ed25519"), key.ed25519.hex())
        assertNull(history.keyAt(key.effectiveFromMs - 1uL))
    }

    @Test
    fun savedStateRestoresAndRefusesARollback() {
        val lc = client()
        val index = lc.sync(transport, clock).index
        val saved = lc.save()
        val back = LightClient.restore(saved, fixture.getLong("chain_id").toULong(), fixture.getString("genesis_hash"), index)
        assertEquals(index, back.latest()!!.index)
        assertFailsWith<LightException> {
            LightClient.restore(saved, fixture.getLong("chain_id").toULong(), fixture.getString("genesis_hash"), index + 1u)
        }
    }

    @Test
    fun nothingIsReadBeforeACheckpointIsCertified() {
        assertFailsWith<LightException.NotSynced> {
            client().resolveIdentity(transport, expect.getJSONObject("identity").getString("did"), clock)
        }
    }

    @Test
    fun aTransportFailureIsReported() {
        val down = object : Transport {
            override fun call(method: String, paramsJson: String): String =
                throw TransportException.Failed("connection refused")
        }
        assertFailsWith<LightException> { client().sync(down, clock) }
    }
}
