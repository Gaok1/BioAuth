package com.bioauth.phone_auth_native

/**
 * The Public Suffix List, used to reject a relying party that is not a
 * registrable domain.
 *
 * WebAuthn requires the RP ID to be a *registrable* domain suffix of the
 * origin, not merely a suffix. Without this, a page on `evil.com.br` may claim
 * `rpId = "com.br"`: the credential is then stored under a suffix that every
 * other `*.com.br` site can ask for. The private section of the list matters
 * most here — `github.io`, `vercel.app`, `pages.dev` are exactly the domains
 * where an attacker can host a page without owning the parent domain.
 *
 * The list is bundled verbatim from https://publicsuffix.org/list/, MPL-2.0,
 * so it can be re-pulled and diffed. Refresh it periodically; a stale list does
 * not weaken suffixes that already existed, it only misses newer ones.
 */
internal class PublicSuffixList(lines: Sequence<String>) {
    private val rules: Set<String>
    private val exceptions: Set<String>

    init {
        val plain = HashSet<String>()
        val exception = HashSet<String>()
        for (raw in lines) {
            // Entries are one rule per line; anything after whitespace and any
            // `//` line is commentary.
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("//")) continue
            val rule = line.substringBefore(' ').substringBefore('\t').lowercase()
            if (rule.isEmpty()) continue
            if (rule.startsWith("!")) exception.add(rule.substring(1)) else plain.add(rule)
        }
        rules = plain
        exceptions = exception
    }

    /**
     * Whether nothing may be scoped to [host] because it is itself a public
     * suffix — a bare TLD, `com.br`, or `github.io`.
     */
    fun isPublicSuffix(host: String): Boolean = publicSuffixOf(host) == host

    /** The public suffix governing [host], by the algorithm at publicsuffix.org. */
    fun publicSuffixOf(host: String): String {
        val labels = host.lowercase().split('.').filter { it.isNotEmpty() }
        if (labels.isEmpty()) return ""

        // An exception rule wins outright, and its public suffix is the rule
        // without its leftmost label. Scanning from the left finds the longest.
        for (index in labels.indices) {
            val candidate = labels.subList(index, labels.size)
            if (candidate.joinToString(".") in exceptions) {
                return candidate.drop(1).joinToString(".")
            }
        }

        for (index in labels.indices) {
            val candidate = labels.subList(index, labels.size)
            val joined = candidate.joinToString(".")
            if (joined in rules) return joined
            if (candidate.size > 1) {
                val wildcard = (listOf("*") + candidate.drop(1)).joinToString(".")
                if (wildcard in rules) return joined
            }
        }

        // No rule matched, so the implicit `*` rule applies and the rightmost
        // label is the public suffix.
        return labels.last()
    }
}
