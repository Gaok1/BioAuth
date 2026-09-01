package com.bioauth.phone_auth_native

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class VaultAutofillMatcherTest {
    @Test
    fun `a browser origin matches only the exact host`() {
        val items = listOf(
            item("bank", "https://bank.example.com/login"),
            item("other", "https://other.example.com/"),
        )

        val matched = VaultAutofillMatcher.matches(
            items,
            AutofillCaller(origin = "https://bank.example.com"),
        ) { false }

        assertEquals(listOf("bank"), matched.map { it.id })
    }

    /**
     * `login.bank.example` and `blog.bank.example` share a registrable domain
     * and are not the same place to type a password into. Widening to eTLD+1
     * is the most common way autofill hands over the wrong credential.
     */
    @Test
    fun `a sibling subdomain is not a match`() {
        val items = listOf(item("bank", "https://login.bank.example/"))

        val matched = VaultAutofillMatcher.matches(
            items,
            AutofillCaller(origin = "https://blog.bank.example"),
        ) { false }

        assertTrue(matched.isEmpty())
    }

    @Test
    fun `a native app matches an item that names its package`() {
        val items = listOf(
            item("app", "androidapp://com.example.app"),
            item("other", "androidapp://com.other.app"),
        )

        val matched = VaultAutofillMatcher.matches(
            items,
            AutofillCaller(packageName = "com.example.app"),
        ) { false }

        assertEquals(listOf("app"), matched.map { it.id })
    }

    /**
     * The site has to say so. Without a Digital Asset Links statement there is
     * nothing connecting an app to a website except the name, and names are
     * free.
     */
    @Test
    fun `a native app matches a site only when the site authorizes it`() {
        val items = listOf(item("bank", "https://bank.example/login"))
        val caller = AutofillCaller(packageName = "com.bank.app")

        val unauthorized = VaultAutofillMatcher.matches(items, caller) { false }
        val authorized = VaultAutofillMatcher.matches(items, caller) { it == "bank.example" }

        assertTrue(unauthorized.isEmpty())
        assertEquals(listOf("bank"), authorized.map { it.id })
    }

    /**
     * The heuristic every autofill bug is made of: a package name that looks
     * like a reversed host is not a statement by anybody.
     */
    @Test
    fun `a package name resembling the host proves nothing`() {
        val items = listOf(item("bank", "https://bank.example/"))

        val matched = VaultAutofillMatcher.matches(
            items,
            AutofillCaller(packageName = "example.bank"),
        ) { false }

        assertTrue(matched.isEmpty())
    }

    /** One autofill prompt must not become one network request per site. */
    @Test
    fun `asset link checks are capped and deduplicated`() {
        val items = (1..40).map { item("i$it", "https://site$it.example/") } +
            (1..5).map { item("dup$it", "https://same.example/") }
        var checks = 0

        VaultAutofillMatcher.matches(items, AutofillCaller(packageName = "com.x")) {
            checks++
            false
        }

        assertTrue(
            checks <= VaultAutofillMatcher.MAX_HOSTS_VERIFIED,
            "made $checks asset-link checks",
        )
    }

    @Test
    fun `an item matching both ways is offered once`() {
        val items = listOf(item("both", "androidapp://com.example.app"))

        val matched = VaultAutofillMatcher.matches(
            items,
            AutofillCaller(packageName = "com.example.app"),
        ) { true }

        assertEquals(1, matched.size)
    }

    @Test
    fun `notes are never offered for autofill`() {
        val items = listOf(item("note", "https://bank.example/", kind = 1))

        val matched = VaultAutofillMatcher.matches(
            items,
            AutofillCaller(origin = "https://bank.example"),
        ) { true }

        assertTrue(matched.isEmpty())
    }

    @Test
    fun `a caller that is neither matches nothing`() {
        val items = listOf(item("bank", "https://bank.example/"))

        assertTrue(VaultAutofillMatcher.matches(items, AutofillCaller()) { true }.isEmpty())
    }

    /**
     * Userinfo in a URI is the classic way to make a host read as one thing
     * and resolve as another.
     */
    @Test
    fun `host parsing ignores credentials ports and case`() {
        assertEquals("bank.example", VaultAutofillMatcher.hostOf("https://bank.example:8443/x"))
        assertEquals("bank.example", VaultAutofillMatcher.hostOf("https://BANK.example/"))
        assertEquals(
            "real.example",
            VaultAutofillMatcher.hostOf("https://bank.example@real.example/"),
        )
        assertEquals(null, VaultAutofillMatcher.hostOf(""))
        assertEquals(null, VaultAutofillMatcher.hostOf("androidapp://com.example"))
    }

    /**
     * The address field holds what a person typed, not an origin.
     *
     * Requiring `https://` there meant every item saved the way people write
     * addresses was offered for no site at all -- and a matcher that finds
     * nothing is indistinguishable from a vault that holds nothing.
     */
    @Test
    fun `an address may be written the way a person writes one`() {
        for (written in listOf(
            "bank.example",
            "https://bank.example",
            "http://bank.example/login",
            "  bank.example/login?next=/  ",
            "bank.example:8443",
            "BANK.example",
        )) {
            assertEquals("bank.example", VaultAutofillMatcher.hostOf(written), written)
        }
    }

    /**
     * Only the item's address is read leniently. The origin says who is
     * asking, and a scheme-less string is not one.
     */
    @Test
    fun `the origin that decides who is asking is not read leniently`() {
        assertEquals("bank.example", VaultAutofillMatcher.originHost("https://bank.example/"))
        assertEquals(null, VaultAutofillMatcher.originHost("bank.example"))
        assertEquals(null, VaultAutofillMatcher.originHost(""))
        assertEquals(
            "real.example",
            VaultAutofillMatcher.originHost("https://bank.example@real.example/"),
        )
    }

    /** Looser on the address is not looser on the match. */
    @Test
    fun `a scheme-less address still matches only its own host`() {
        assertEquals("real.example", VaultAutofillMatcher.hostOf("bank.example@real.example/"))
        assertNotEquals(
            VaultAutofillMatcher.hostOf("blog.bank.example"),
            VaultAutofillMatcher.hostOf("login.bank.example"),
        )
        // A field holding a sentence is not an address, and matches nothing
        // rather than matching loosely.
        assertEquals(null, VaultAutofillMatcher.hostOf("minha senha do banco"))
        assertEquals(null, VaultAutofillMatcher.hostOf("https://"))
    }

    @Test
    fun `package parsing rejects what is not a package`() {
        assertEquals(
            "com.example.app",
            VaultAutofillMatcher.packageOf("androidapp://com.example.app"),
        )
        assertEquals(
            "com.example.app",
            VaultAutofillMatcher.packageOf("androidapp://com.example.app/x"),
        )
        assertEquals(null, VaultAutofillMatcher.packageOf("androidapp://"))
        assertEquals(null, VaultAutofillMatcher.packageOf("https://example.com"))
    }

    /** The type the matcher works on has no field a secret could travel in. */
    @Test
    fun `a candidate cannot carry a secret`() {
        val candidate = AutofillCandidate.of(
            VaultItem(
                id = "one",
                revision = 1,
                kind = 0,
                name = "Banco",
                username = "alice",
                uri = "https://bank.example/",
                secret = "hunter2",
                updatedAtMs = 0,
            ),
        )

        assertTrue(!candidate.toString().contains("hunter2"))
    }

    private fun item(id: String, uri: String, kind: Int = 0) =
        AutofillCandidate(id = id, kind = kind, name = id, username = "alice", uri = uri)
}
