package com.bioauth.phone_auth_native

/**
 * Decides which vault items may be offered to the app or page that is asking.
 *
 * This is the whole security surface of password autofill. Offering an entry
 * is telling the user "this is your account here", and a user who taps it has
 * no way to audit the claim. A matcher that guesses hands a bank password to
 * whatever installed itself last week.
 *
 * So it never guesses. Two ways an item can match, both exact:
 *
 * - **A browser with a verified origin.** The host must equal the item's host,
 *   character for character. No registrable-domain widening: `login.bank.com`
 *   and `blog.bank.com` are the same registrable domain and not the same
 *   place to type a password into.
 * - **A native app.** Either the item names the package outright
 *   (`androidapp://com.example.app`), or the site the item belongs to
 *   published a Digital Asset Links statement delegating
 *   `delegate_permission/common.get_login_creds` to that package and signing
 *   certificate — the same check the passkey path already performs, and the
 *   relation is literally the one for passwords.
 *
 * Everything else is no match, including a host that merely looks like the
 * package name reversed. That heuristic is what most autofill bugs are.
 */
internal object VaultAutofillMatcher {
    /** Hosts checked against asset links in one request. */
    const val MAX_HOSTS_VERIFIED = 8

    /** `VaultItem.kind` for a login. Notes have no username to fill. */
    private const val KIND_LOGIN = 0

    /** URIs that name an Android package directly, rather than a site. */
    private const val APP_SCHEME = "androidapp://"

    /**
     * @param authorizes answers whether `host` published a statement
     *   delegating login credentials to the calling app. Injected so the
     *   matching rules are testable without a network.
     */
    fun matches(
        items: List<AutofillCandidate>,
        caller: AutofillCaller,
        authorizes: (String) -> Boolean,
    ): List<AutofillCandidate> {
        val logins = items.filter { it.kind == KIND_LOGIN }

        caller.origin?.let { origin ->
            // Two parsers on purpose, and only one of them is lenient. The
            // caller's origin comes from the platform and is a real origin;
            // the item's address is whatever a person typed into a field.
            val host = originHost(origin) ?: return emptyList()
            return logins.filter { hostOf(it.uri) == host }
        }

        val packageName = caller.packageName ?: return emptyList()
        val explicit = logins.filter { packageOf(it.uri) == packageName }

        // Asset links cost a network round trip each, so the hosts are
        // deduplicated and capped. A vault with a thousand sites must not turn
        // one autofill prompt into a thousand requests.
        val verified = mutableSetOf<String>()
        val checked = mutableSetOf<String>()
        for (item in logins) {
            val host = hostOf(item.uri) ?: continue
            if (!checked.add(host)) continue
            if (checked.size > MAX_HOSTS_VERIFIED) break
            if (authorizes(host)) verified.add(host)
        }

        // One item can match both ways; the result must not list it twice.
        val byHost = logins.filter { hostOf(it.uri) in verified }
        return (explicit + byHost).distinctBy { it.id }
    }

    /**
     * The host of a URI, lowercased, or null when there is not one.
     *
     * Written by hand rather than with `android.net.Uri` so it runs in a JVM
     * test, and because the rules wanted here are narrower than a general
     * parser's: a port is not part of a host, and userinfo is not a host at all.
     */
    fun hostOf(uri: String): String? {
        val value = uri.trim()
        if (value.isEmpty() || value.startsWith(APP_SCHEME)) return null
        // The scheme is optional, and that is not a relaxation of the match.
        // Somebody filling in "endereço" writes `github.com`; `https://` is not
        // part of what they think they are saying. Requiring it meant an item
        // saved that way was offered for no site at all -- silently, since a
        // matcher that finds nothing looks exactly like a vault that holds
        // nothing. What follows is unchanged, and the comparison at the call
        // sites is still character-for-character against a verified origin.
        val afterScheme = if (value.contains("://")) {
            value.substringAfter("://")
        } else {
            value
        }
        return authorityHost(afterScheme)
    }

    /**
     * The host of an origin the platform reported, or null.
     *
     * A scheme-less string is not an origin. This side stays strict because it
     * decides *who is asking*, and the only reason [hostOf] is not is that it
     * reads a field a person filled in.
     */
    fun originHost(origin: String): String? {
        val value = origin.trim()
        if (!value.contains("://")) return null
        return authorityHost(value.substringAfter("://"))
    }

    private fun authorityHost(afterScheme: String): String? {
        if (afterScheme.isEmpty()) return null
        val authority = afterScheme
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
        // Credentials in a URI are the classic way to make a host read as one
        // thing and resolve as another.
        val host = authority.substringAfterLast('@').substringBefore(':')
        if (host.isEmpty() || host.any(Char::isWhitespace)) return null
        return host.lowercase()
    }

    /** The package an `androidapp://` URI names, or null. */
    fun packageOf(uri: String): String? {
        if (!uri.startsWith(APP_SCHEME)) return null
        val name = uri.removePrefix(APP_SCHEME).substringBefore('/').trim()
        return name.takeIf { it.isNotEmpty() && it.none(Char::isWhitespace) }
    }
}

/**
 * Who is asking.
 *
 * Exactly one of these is set. A browser that Android trusts to speak for a
 * web origin reports that origin; everything else reports its package name and
 * has to earn a match.
 */
internal data class AutofillCaller(
    val origin: String? = null,
    val packageName: String? = null,
)

/**
 * A vault item as the matcher sees it.
 *
 * Deliberately narrower than [VaultItem]: matching decides what to *offer*,
 * and offering needs an id, a kind and a place. A type with a `secret` field
 * would put every password through this code for no reason, and the reason a
 * type has no field is the only durable way to say a value never travels.
 */
internal data class AutofillCandidate(
    val id: String,
    val kind: Int,
    val name: String,
    val username: String,
    val uri: String,
) {
    companion object {
        fun of(item: VaultItem) = AutofillCandidate(
            id = item.id,
            kind = item.kind,
            name = item.name,
            username = item.username,
            uri = item.uri,
        )
    }
}
