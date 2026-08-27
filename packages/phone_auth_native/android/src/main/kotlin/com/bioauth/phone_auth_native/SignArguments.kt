package com.bioauth.phone_auth_native

internal data class SignArguments(
    val payload: ByteArray,
    val title: String,
    val subtitle: String,
    val description: String,
) {
    companion object {
        fun parse(arguments: Any?): SignArguments {
            val map = arguments as? Map<*, *> ?: throw IllegalArgumentException("Missing arguments")
            val payload = map["payload"] as? ByteArray
                ?: throw IllegalArgumentException("Missing canonical payload")
            require(payload.isNotEmpty() && payload.size <= 8192) { "Invalid canonical payload size" }
            val context = map["context"] as? Map<*, *>
                ?: throw IllegalArgumentException("Missing authentication context")
            return SignArguments(
                payload = payload.copyOf(),
                title = context.requiredText("title", 64),
                subtitle = context.requiredText("subtitle", 128),
                description = context.requiredText("description", 256),
            )
        }

        private fun Map<*, *>.requiredText(key: String, maxLength: Int): String {
            val value = this[key] as? String ?: throw IllegalArgumentException("Missing $key")
            require(value.isNotBlank() && value.length <= maxLength) { "Invalid $key" }
            return value.trim()
        }
    }
}
