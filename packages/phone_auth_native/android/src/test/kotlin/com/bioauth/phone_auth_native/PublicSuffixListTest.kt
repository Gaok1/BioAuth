package com.bioauth.phone_auth_native

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class PublicSuffixListTest {
    private val bundled = PublicSuffixList(
        File("src/main/res/raw/public_suffix_list.dat").readLines().asSequence(),
    )

    /**
     * Guards the shipped file itself. An empty or truncated list still parses,
     * and every rule it is missing silently becomes a registrable domain — the
     * exact hole this list exists to close.
     */
    @Test
    fun theBundledListCoversIcannAndPrivateSuffixes() {
        for (suffix in listOf("com", "org", "co.uk", "com.br", "com.au", "co.jp")) {
            assertTrue(bundled.isPublicSuffix(suffix), "`$suffix` must be a public suffix")
        }
        // The private section is where an attacker can host a page without
        // owning the parent domain, so it has to be present too.
        for (suffix in listOf("github.io", "vercel.app", "pages.dev", "herokuapp.com")) {
            assertTrue(bundled.isPublicSuffix(suffix), "`$suffix` must be a public suffix")
        }
    }

    @Test
    fun ordinaryDomainsStayRegistrable() {
        for (host in listOf("example.com", "shop.com.br", "mine.github.io", "bbc.co.uk")) {
            assertFalse(bundled.isPublicSuffix(host), "`$host` must stay registrable")
        }
    }

    @Test
    fun theLongestMatchingRuleWins() {
        assertEquals("com.br", bundled.publicSuffixOf("shop.com.br"))
        assertEquals("co.uk", bundled.publicSuffixOf("bbc.co.uk"))
        assertEquals("github.io", bundled.publicSuffixOf("mine.github.io"))
    }

    @Test
    fun wildcardRulesAndTheirExceptionsAreHonoured() {
        val list = PublicSuffixList(sequenceOf("ck", "*.ck", "!www.ck"))
        assertEquals("foo.ck", list.publicSuffixOf("bar.foo.ck"))
        assertTrue(list.isPublicSuffix("foo.ck"))
        // The exception pulls `www.ck` back out, making it registrable.
        assertEquals("ck", list.publicSuffixOf("www.ck"))
        assertFalse(list.isPublicSuffix("www.ck"))
    }

    @Test
    fun anUnknownTopLevelDomainFallsBackToTheImplicitWildcard() {
        val list = PublicSuffixList(sequenceOf("com"))
        assertEquals("invalid", list.publicSuffixOf("host.invalid"))
        assertTrue(list.isPublicSuffix("invalid"))
    }

    @Test
    fun commentsAndBlankLinesAreIgnored() {
        val list = PublicSuffixList(sequenceOf("// VERSION: test", "", "  ", "com"))
        assertTrue(list.isPublicSuffix("com"))
        assertFalse(list.isPublicSuffix("// VERSION: test"))
    }
}
