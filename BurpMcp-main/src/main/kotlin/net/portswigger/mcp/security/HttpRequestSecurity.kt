package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import java.net.URI
import javax.swing.SwingUtilities
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

interface UserApprovalHandler {
    suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String? = null, api: MontoyaApi? = null
    ): Boolean
}

class SwingUserApprovalHandler : UserApprovalHandler {
    override suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String?, api: MontoyaApi?
    ): Boolean {
        return suspendCoroutine { continuation ->
            SwingUtilities.invokeLater {
                val message = buildString {
                    appendLine("An MCP client is requesting to send an HTTP request to:")
                    appendLine()
                    appendLine("Target: $hostname:$port")
                    appendLine()
                }

                val options = arrayOf(
                    "Allow Once", "Always Allow Host", "Always Allow Host:Port", "Deny"
                )

                val burpFrame = findBurpFrame()

                val result = Dialogs.showOptionDialog(
                    burpFrame, message, options, requestContent, api
                )

                when (result) {
                    0 -> {
                        continuation.resume(true)
                    }

                    1 -> {
                        config.addAutoApproveTarget(hostname)
                        continuation.resume(true)
                    }

                    2 -> {
                        config.addAutoApproveTarget("$hostname:$port")
                        continuation.resume(true)
                    }

                    else -> {
                        continuation.resume(false)
                    }
                }
            }
        }
    }
}

object HttpRequestSecurity {

    var approvalHandler: UserApprovalHandler = SwingUserApprovalHandler()

    private fun isAutoApproved(
        hostname: String,
        port: Int,
        config: McpConfig,
        usesHttps: Boolean? = null,
        requestPath: String? = null
    ): Boolean {
        val target = "$hostname:$port"
        val hostOnly = hostname
        val targets = config.getAutoApproveTargetsList()

        return targets.any { approved ->
            when {
                approved.startsWith("http://", ignoreCase = true) || approved.startsWith("https://", ignoreCase = true) -> {
                    val approvedUri = runCatching { URI(approved) }.getOrNull() ?: return@any false
                    if (!approvedUri.host.equals(hostname, ignoreCase = true)) return@any false

                    val expectedScheme = if (usesHttps == true) "https" else "http"
                    if (!approvedUri.scheme.equals(expectedScheme, ignoreCase = true)) return@any false

                    val approvedPort = when {
                        approvedUri.port != -1 -> approvedUri.port
                        approvedUri.scheme.equals("https", ignoreCase = true) -> 443
                        else -> 80
                    }
                    if (approvedPort != port) return@any false

                    val prefix = approvedUri.path.orEmpty().ifBlank { "/" }
                    val candidatePath = requestPath.orEmpty().ifBlank { "/" }
                    candidatePath.startsWith(prefix)
                }

                approved.equals(target, ignoreCase = true) -> true

                approved.equals(hostOnly, ignoreCase = true) -> true

                approved.startsWith("*.") -> {
                    val domain = approved.substring(2)
                    isValidWildcardMatch(hostname, domain)
                }

                else -> false
            }
        }
    }

    private fun isValidWildcardMatch(hostname: String, domain: String): Boolean {
        if (domain.isEmpty() || domain.contains("*")) return false

        if (hostname.length <= domain.length) return false

        val expectedSuffix = ".$domain"
        if (!hostname.endsWith(expectedSuffix, ignoreCase = true)) return false

        val subdomain = hostname.substring(0, hostname.length - expectedSuffix.length)

        if (subdomain.isEmpty()) return false

        return subdomain.split(".").all { label ->
            label.isNotEmpty() && label.length <= 63 && !label.startsWith("-") && !label.endsWith("-") && label.matches(
                Regex("^[a-zA-Z0-9-]+$")
            )
        }
    }

    suspend fun checkHttpRequestPermission(
        hostname: String,
        port: Int,
        config: McpConfig,
        requestContent: String? = null,
        api: MontoyaApi? = null,
        usesHttps: Boolean? = null,
        requestPath: String? = null
    ): Boolean {
        if (!config.requireHttpRequestApproval) {
            return true
        }

        if (isAutoApproved(hostname, port, config, usesHttps, requestPath)) {
            return true
        }

        return approvalHandler.requestApproval(hostname, port, config, requestContent, api)
    }
}
