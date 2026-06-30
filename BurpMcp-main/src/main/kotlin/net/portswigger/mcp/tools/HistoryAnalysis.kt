package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import java.net.URI
import java.security.MessageDigest
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

private val HISTORY_JSON = Json {
    prettyPrint = true
    encodeDefaults = true
}

private val sensitiveNameRegex =
    Regex("(?i)(auth|token|csrf|secret|key|session|cookie|jwt|bearer|password|passwd|otp|code)")
private val redirectNameRegex = Regex("(?i)(next|redirect|return|returnto|continue|dest|destination|url|redirect_uri)")
private val ssrfNameRegex = Regex("(?i)(url|uri|feed|dest|destination|endpoint|proxy|callback|webhook|image|file)")
private val objectIdNameRegex = Regex("(?i)(^id$|_id$|Id$|user|account|profile|order|invoice|project|org|tenant|member)")
private val authPathRegex = Regex("(?i)/(admin|account|profile|settings|billing|users?|teams?|orgs?|tenants?|projects?)(/|$)")
private val stackTraceRegex = Regex("(?i)(exception|stack trace|traceback|syntax error|sql syntax|undefined index|nullpointerexception)")
private val secretRegex = Regex("(?i)(api[_-]?key|secret[_-]?key|aws_access_key_id|authorization: bearer|x-api-key)")
private val wildcardOriginRegex = Regex("(?i)^\\*$")
private val reflectedOriginRegex = Regex("(?i)^https?://")
private val numericValueRegex = Regex("^-?\\d{1,18}$")
private val uuidRegex =
    Regex("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
private val hexIdRegex = Regex("(?i)^[0-9a-f]{16,64}$")

internal inline fun <reified T> toPrettyJson(value: T): String = HISTORY_JSON.encodeToString(value)

internal fun getFilteredHistory(api: MontoyaApi, config: McpConfig, inScopeOnly: Boolean = config.onlyReturnInScopeHistory): List<ProxyHttpRequestResponse> {
    val history = api.proxy().history()
    if (!inScopeOnly) {
        return history.toList()
    }

    return history.filter { item ->
        val request = item.request()
        request != null && runCatching { api.scope().isInScope(request.url()) }.getOrDefault(false)
    }
}

internal fun historyEntryFromRef(
    api: MontoyaApi,
    config: McpConfig,
    ref: String,
    inScopeOnly: Boolean = config.onlyReturnInScopeHistory
): HistoryEntry? {
    return getFilteredHistory(api, config, inScopeOnly)
        .asSequence()
        .mapNotNull { item -> item.toHistoryEntry(api) }
        .firstOrNull { it.ref.ref == ref }
}

internal fun ProxyHttpRequestResponse.toHistoryEntry(api: MontoyaApi): HistoryEntry? {
    val request = request() ?: return null
    val response = response()
    val method = runCatching { request.method() }.getOrElse { return null }
    val url = runCatching { request.url() }.getOrElse { return null }
    val uri = runCatching { URI(url) }.getOrNull()
    val host = uri?.host ?: runCatching { request.httpService().host() }.getOrDefault("")
    val path = runCatching { request.pathWithoutQuery() }.getOrElse { uri?.path ?: "/" }
    val query = runCatching { request.query() }.getOrNull()
    val normalizedRoute = normalizeRoute(path)
    val authHints = detectAuthHints(request)
    val requestHeaders = request.headers().associate { it.name() to it.value() }
    val parameterValues = request.parameters().map {
        ObservedParameter(
            name = it.name(),
            value = it.value(),
            type = it.type().name
        )
    }
    val responseHeaders = response?.headers()?.associate { it.name() to it.value() }.orEmpty()
    val responseStatus = response?.statusCode()?.toInt()
    val responseMimeType = runCatching { response?.statedMimeType()?.toString() ?: response?.mimeType()?.toString() }.getOrNull()
    val requestBody = runCatching { request.bodyToString() }.getOrDefault("")
    val responseBody = runCatching { response?.bodyToString().orEmpty() }.getOrDefault("")
    val bodyLength = runCatching { response?.body()?.length() ?: responseBody.length }.getOrDefault(responseBody.length)
    val inScope = runCatching { api.scope().isInScope(url) }.getOrDefault(false)

    val ref = HistoryRef(
        ref = buildHistoryRef(method, url, responseStatus, request.toString()),
        method = method,
        url = url,
        host = host,
        inScope = inScope,
        statusCode = responseStatus,
        note = annotations().notes()
    )

    return HistoryEntry(
        ref = ref,
        request = request,
        response = response,
        path = path,
        query = query,
        normalizedRoute = normalizedRoute,
        authHints = authHints.sorted(),
        requestHeaders = requestHeaders,
        responseHeaders = responseHeaders,
        requestBody = requestBody,
        responseBody = responseBody,
        responseMimeType = responseMimeType,
        responseBodyLength = bodyLength,
        parameters = parameterValues
    )
}

internal fun normalizeRoute(path: String): String {
    if (path.isBlank()) {
        return "/"
    }

    val normalized = path.split('/')
        .filter { it.isNotEmpty() }
        .joinToString(prefix = "/", separator = "/") { segment ->
            when {
                numericValueRegex.matches(segment) -> "{id}"
                uuidRegex.matches(segment) -> "{uuid}"
                hexIdRegex.matches(segment) -> "{token}"
                else -> segment
            }
        }

    return if (normalized.isBlank()) "/" else normalized
}

internal fun buildHistoryRef(method: String, url: String, statusCode: Int?, requestContent: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val input = listOf(method, url, statusCode?.toString().orEmpty(), requestContent).joinToString("\u0000")
    return digest.digest(input.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}

internal fun summarizeHistory(
    entries: List<HistoryEntry>,
    groupByRoute: Boolean
): HistorySummaryResult {
    if (!groupByRoute) {
        return HistorySummaryResult(
            grouped = false,
            itemCount = entries.size,
            endpointCount = 0,
            endpoints = emptyList(),
            items = entries.map { it.toItemSummary() }
        )
    }

    val endpoints = entries.groupBy { "${it.ref.host}|${it.normalizedRoute}" }
        .values
        .map { group ->
            val first = group.first()
            val parameterSummaries = group.flatMap { it.parameters }
                .groupBy { "${it.type}:${it.name.lowercase()}" }
                .values
                .map { params ->
                    val sampleValues = params.map { it.value }.filter { it.isNotBlank() }.distinct().take(5)
                    EndpointParameterSummary(
                        name = params.first().name,
                        types = params.map { it.type }.distinct().sorted(),
                        sampleValues = sampleValues,
                        distinctValueCount = params.map { it.value }.distinct().size,
                        looksSensitive = sensitiveNameRegex.containsMatchIn(params.first().name),
                        looksNumeric = sampleValues.any { numericValueRegex.matches(it) }
                    )
                }
                .sortedBy { it.name.lowercase() }

            EndpointSummary(
                host = first.ref.host,
                route = first.normalizedRoute,
                methods = group.map { it.ref.method }.distinct().sorted(),
                frequency = group.size,
                authHints = group.flatMap { it.authHints }.distinct().sorted(),
                requestContentTypes = group.mapNotNull { it.requestHeaders["Content-Type"] }.distinct().sorted(),
                responseContentTypes = group.mapNotNull { it.responseMimeType ?: it.responseHeaders["Content-Type"] }.distinct().sorted(),
                statusCodes = group.mapNotNull { it.ref.statusCode }.groupingBy { it }.eachCount().toSortedMap(),
                parameters = parameterSummaries,
                sampleRefs = group.take(5).map { it.ref.ref }
            )
        }
        .sortedWith(compareBy<EndpointSummary>({ it.host }, { it.route }))

    return HistorySummaryResult(
        grouped = true,
        itemCount = entries.size,
        endpointCount = endpoints.size,
        endpoints = endpoints,
        items = emptyList()
    )
}

internal fun analyzeHistory(
    entries: List<HistoryEntry>,
    requestedProfiles: List<String>
): HistoryAnalysisResult {
    val profiles = normalizeProfiles(requestedProfiles)
    val findings = buildList {
        if ("idor" in profiles) addAll(findIdorCandidates(entries))
        if ("auth" in profiles) addAll(findAuthCandidates(entries))
        if ("input" in profiles) addAll(findInputSurface(entries))
        if ("cors" in profiles) addAll(findCorsCandidates(entries))
        if ("cache" in profiles) addAll(findCacheCandidates(entries))
        if ("secrets" in profiles || "debug" in profiles) addAll(findSecretAndDebugCandidates(entries, profiles))
        if ("ssrf" in profiles) addAll(findSsrfCandidates(entries))
        if ("websocket" in profiles) addAll(findWebSocketCandidates(entries))
    }
        .distinctBy { it.findingId }
        .sortedWith(compareByDescending<PassiveFinding> { severityRank(it.severity) }.thenBy { it.category }.thenBy { it.findingId })

    return HistoryAnalysisResult(
        itemCount = entries.size,
        consideredProfiles = profiles.sorted(),
        findings = findings
    )
}

internal fun createVerificationPlan(
    entry: HistoryEntry,
    checkType: String,
    payloadValue: String? = null
): VerificationPlan {
    val variants = generateVerificationVariants(entry, checkType, payloadValue)

    return VerificationPlan(
        historyRef = entry.ref.ref,
        checkType = checkType.lowercase(),
        variants = variants.map { it.preview() }
    )
}

internal fun generateVerificationVariants(
    entry: HistoryEntry,
    checkType: String,
    payloadValue: String? = null
): List<VerificationVariant> {
    return when (checkType.lowercase()) {
        "idor" -> generateIdorVariants(entry)
        "method_tampering" -> generateMethodVariants(entry)
        "auth_header_drop" -> generateAuthDropVariants(entry)
        "origin_header" -> generateOriginVariants(entry)
        "cache_poisoning_basic" -> generateCacheVariants(entry)
        "open_redirect" -> generateOpenRedirectVariants(entry)
        "ssrf_candidate" -> generateSsrfVariants(entry, payloadValue)
        "numeric_boundary" -> generateNumericBoundaryVariants(entry)
        else -> emptyList()
    }
}

internal fun executeVerificationPlan(
    api: MontoyaApi,
    config: McpConfig,
    entry: HistoryEntry,
    checkType: String,
    variants: List<VerificationVariant>,
    safeMode: Boolean,
    maxRequests: Int,
    previewOnly: Boolean
): VerificationExecutionResult {
    val baseline = snapshotResponse(entry.response)
    val selectedVariants = variants.take(max(0, maxRequests))
    if (previewOnly) {
        return VerificationExecutionResult(
            historyRef = entry.ref.ref,
            checkType = checkType,
            safeMode = safeMode,
            previewOnly = true,
            baseline = baseline,
            variants = selectedVariants.map {
                ExecutedVerificationVariant(
                    id = it.id,
                    title = it.title,
                    expectedSignal = it.expectedSignal,
                    requestPreview = it.rawRequest,
                    response = null,
                    observations = listOf("Preview only; request was not sent.")
                )
            },
            conclusion = "Preview only",
            followUp = "Review the generated requests and rerun with previewOnly=false when ready."
        )
    }

    val executed = selectedVariants.map { variant ->
        val allowed = kotlinx.coroutines.runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(
                hostname = variant.targetHost,
                port = variant.targetPort,
                config = config,
                requestContent = variant.rawRequest,
                api = api,
                usesHttps = variant.usesHttps,
                requestPath = variant.path
            )
        }
        if (!allowed) {
            ExecutedVerificationVariant(
                id = variant.id,
                title = variant.title,
                expectedSignal = variant.expectedSignal,
                requestPreview = variant.rawRequest,
                response = null,
                observations = listOf("Request denied by Burp Suite approval policy.")
            )
        } else {
            val response = sendVariant(api, variant)
            val snapshot = snapshotResponse(response)
            ExecutedVerificationVariant(
                id = variant.id,
                title = variant.title,
                expectedSignal = variant.expectedSignal,
                requestPreview = variant.rawRequest,
                response = snapshot,
                observations = compareResponses(checkType, baseline, snapshot, variant)
            )
        }
    }

    val conclusion = buildConclusion(checkType, executed)
    val followUp = when {
        executed.any { it.observations.any { obs -> obs.contains("Potential", ignoreCase = true) } } ->
            "Promising differential detected. Send the strongest variant to Repeater and validate impact manually."

        else -> "No high-signal differential was observed. Manual review may still be warranted for complex auth and business logic."
    }

    return VerificationExecutionResult(
        historyRef = entry.ref.ref,
        checkType = checkType,
        safeMode = safeMode,
        previewOnly = false,
        baseline = baseline,
        variants = executed,
        conclusion = conclusion,
        followUp = followUp
    )
}

internal fun buildFindingBundle(
    finding: PassiveFinding,
    entries: List<HistoryEntry>
): FindingBundle {
    val relatedEntries = entries.filter { it.ref.ref in finding.historyRefs }
    val suggestedChecks = relatedEntries
        .flatMap { entry ->
            finding.suggestedChecks.map { check ->
                generateVerificationVariants(entry, check)
            }
        }
        .flatten()
        .distinctBy { "${it.id}:${it.rawRequest}" }

    return FindingBundle(
        finding = finding,
        supportingRequests = relatedEntries.map { it.toItemSummary() },
        suggestedVerificationRequests = suggestedChecks.map { it.preview() }
    )
}

private fun sendVariant(api: MontoyaApi, variant: VerificationVariant): HttpResponse? {
    val request = variant.request
    val result = if (variant.httpMode == HttpMode.HTTP_2) {
        api.http().sendRequest(request, HttpMode.HTTP_2)
    } else {
        api.http().sendRequest(request)
    }
    return result?.response()
}

private fun snapshotResponse(response: HttpResponse?): ResponseSnapshot? {
    if (response == null) {
        return null
    }

    val body = runCatching { response.bodyToString() }.getOrDefault("")
    return ResponseSnapshot(
        statusCode = response.statusCode().toInt(),
        reasonPhrase = runCatching { response.reasonPhrase() }.getOrNull(),
        bodyLength = runCatching { response.body().length() }.getOrDefault(body.length),
        location = response.headerValue("Location"),
        cacheControl = response.headerValue("Cache-Control"),
        contentType = response.headerValue("Content-Type"),
        bodyPreview = body.take(300),
        similarityHash = body.lowercase().filter { it.isLetterOrDigit() }.take(200)
    )
}

private fun compareResponses(
    checkType: String,
    baseline: ResponseSnapshot?,
    variant: ResponseSnapshot?,
    request: VerificationVariant
): List<String> {
    if (variant == null) {
        return listOf("No response received.")
    }
    if (baseline == null) {
        return listOf("Baseline response unavailable; compare manually.")
    }

    val observations = mutableListOf<String>()
    if (baseline.statusCode != variant.statusCode) {
        observations += "Status changed from ${baseline.statusCode} to ${variant.statusCode}."
    }

    val lengthDelta = abs(baseline.bodyLength - variant.bodyLength)
    if (lengthDelta > 50) {
        observations += "Body length changed by $lengthDelta bytes."
    }

    val similarity = tokenSimilarity(baseline.bodyPreview, variant.bodyPreview)
    observations += "Approximate body similarity: ${"%.2f".format(similarity)}."

    when (checkType) {
        "auth_header_drop" -> {
            if (variant.statusCode in 200..299 && similarity > 0.85) {
                observations += "Potential auth bypass: removing auth material kept a highly similar successful response."
            }
        }

        "idor" -> {
            if (variant.statusCode in 200..299 && similarity > 0.80) {
                observations += "Potential IDOR/BOLA: alternate object identifier returned a similar successful response."
            }
        }

        "origin_header" -> {
            if (variant.location?.contains("example.org", ignoreCase = true) == true) {
                observations += "Redirect target reflected into Location header."
            }
            if (variant.contentType != null && request.title.contains("CORS", ignoreCase = true)) {
                observations += "Review CORS response headers for reflected origin behaviour."
            }
        }

        "open_redirect" -> {
            if (variant.location?.contains("example.org", ignoreCase = true) == true ||
                variant.bodyPreview.contains("example.org", ignoreCase = true)
            ) {
                observations += "Potential open redirect: attacker-controlled destination appeared in the response."
            }
        }

        "cache_poisoning_basic" -> {
            if (variant.bodyPreview.contains("poison", ignoreCase = true) ||
                variant.location?.contains("poison", ignoreCase = true) == true
            ) {
                observations += "Response reflected cache-poisoning probe values."
            }
        }

        "numeric_boundary" -> {
            if (variant.statusCode >= 500) {
                observations += "Potential validation weakness: boundary value triggered a server error."
            }
        }
    }

    return observations
}

private fun buildConclusion(checkType: String, variants: List<ExecutedVerificationVariant>): String {
    val flattened = variants.flatMap { it.observations }
    return when {
        flattened.any { it.contains("Potential", ignoreCase = true) } ->
            "Potentially interesting differential for $checkType."

        flattened.any { it.startsWith("Status changed") } ->
            "Request variants produced differential behaviour for $checkType, but the signal is weak."

        else -> "No strong differential observed for $checkType."
    }
}

private fun findIdorCandidates(entries: List<HistoryEntry>): List<PassiveFinding> {
    return entries.groupBy { "${it.ref.host}|${it.normalizedRoute}|${it.ref.method}" }
        .values
        .mapNotNull { group ->
            val first = group.first()
            val idParameters = group.flatMap { it.parameters }
                .filter { objectIdNameRegex.containsMatchIn(it.name) && (numericValueRegex.matches(it.value) || uuidRegex.matches(it.value) || hexIdRegex.matches(it.value)) }
            val distinctIds = idParameters.map { it.value }.distinct()
            val pathHasObjectId = first.path.split('/').any { numericValueRegex.matches(it) || uuidRegex.matches(it) || hexIdRegex.matches(it) }

            if (distinctIds.size < 2 && !pathHasObjectId) {
                return@mapNotNull null
            }

            passiveFinding(
                category = "idor",
                severity = if (distinctIds.size >= 3) "medium" else "low",
                confidence = if (distinctIds.size >= 3) "medium" else "low",
                historyRefs = group.take(5).map { it.ref.ref },
                evidence = listOf(
                    "Route `${first.normalizedRoute}` returned multiple object identifiers (${distinctIds.take(5).joinToString(", ")}) across similar requests.",
                    "This route shape is a common BOLA/IDOR candidate for manual authorization checks."
                ),
                suggestedChecks = listOf("idor", "auth_header_drop")
            )
        }
}

private fun findAuthCandidates(entries: List<HistoryEntry>): List<PassiveFinding> {
    return entries.filter { authPathRegex.containsMatchIn(it.path) || it.authHints.isNotEmpty() }
        .mapNotNull { entry ->
            val missingCsrf = entry.ref.method in setOf("POST", "PUT", "PATCH", "DELETE") &&
                entry.requestHeaders.keys.none { it.equals("X-CSRF-Token", ignoreCase = true) || it.equals("X-XSRF-Token", ignoreCase = true) } &&
                !entry.requestBody.contains("csrf", ignoreCase = true)
            val authResponseCacheable = entry.authHints.isNotEmpty() &&
                entry.responseHeaders["Cache-Control"]?.contains("public", ignoreCase = true) == true

            if (!missingCsrf && !authResponseCacheable) {
                return@mapNotNull null
            }

            val evidence = mutableListOf<String>()
            if (missingCsrf) {
                evidence += "State-changing request `${entry.ref.method} ${entry.path}` did not expose an obvious CSRF token in headers or body."
            }
            if (authResponseCacheable) {
                evidence += "Authenticated request returned `Cache-Control: ${entry.responseHeaders["Cache-Control"]}`."
            }

            passiveFinding(
                category = "auth",
                severity = if (authResponseCacheable) "medium" else "low",
                confidence = "low",
                historyRefs = listOf(entry.ref.ref),
                evidence = evidence,
                suggestedChecks = listOf("auth_header_drop", "origin_header")
            )
        }
}

private fun findInputSurface(entries: List<HistoryEntry>): List<PassiveFinding> {
    return entries.filter {
        it.parameters.isNotEmpty() ||
            it.requestHeaders["Content-Type"]?.contains("json", ignoreCase = true) == true ||
            it.requestHeaders["Content-Type"]?.contains("multipart", ignoreCase = true) == true
    }
        .mapNotNull { entry ->
            val interestingNames = entry.parameters.map { it.name }.filter {
                redirectNameRegex.containsMatchIn(it) || ssrfNameRegex.containsMatchIn(it) || objectIdNameRegex.containsMatchIn(it)
            }.distinct()
            if (interestingNames.isEmpty() && entry.parameters.size < 4) {
                return@mapNotNull null
            }

            passiveFinding(
                category = "input",
                severity = "info",
                confidence = "low",
                historyRefs = listOf(entry.ref.ref),
                evidence = listOf(
                    "Endpoint exposes ${entry.parameters.size} parsed parameters${if (interestingNames.isNotEmpty()) " including ${interestingNames.joinToString(", ")}" else ""}.",
                    "This is a good candidate for boundary, redirect, SSRF or access-control validation."
                ),
                suggestedChecks = buildList {
                    add("numeric_boundary")
                    if (interestingNames.any { redirectNameRegex.containsMatchIn(it) }) add("open_redirect")
                    if (interestingNames.any { ssrfNameRegex.containsMatchIn(it) }) add("ssrf_candidate")
                    if (interestingNames.any { objectIdNameRegex.containsMatchIn(it) }) add("idor")
                }.distinct()
            )
        }
}

private fun findCorsCandidates(entries: List<HistoryEntry>): List<PassiveFinding> {
    return entries.mapNotNull { entry ->
        val acao = entry.responseHeaders["Access-Control-Allow-Origin"] ?: return@mapNotNull null
        val acac = entry.responseHeaders["Access-Control-Allow-Credentials"]
        val evidence = mutableListOf<String>()
        if (wildcardOriginRegex.matches(acao)) {
            evidence += "Response returned `Access-Control-Allow-Origin: *`."
        }
        if (reflectedOriginRegex.matches(acao) && acac.equals("true", ignoreCase = true)) {
            evidence += "Response returned a specific ACAO value with `Access-Control-Allow-Credentials: true`."
        }
        if (evidence.isEmpty()) {
            return@mapNotNull null
        }

        passiveFinding(
            category = "cors",
            severity = if (acac.equals("true", ignoreCase = true)) "medium" else "low",
            confidence = "medium",
            historyRefs = listOf(entry.ref.ref),
            evidence = evidence,
            suggestedChecks = listOf("origin_header")
        )
    }
}

private fun findCacheCandidates(entries: List<HistoryEntry>): List<PassiveFinding> {
    return entries.mapNotNull { entry ->
        val cacheControl = entry.responseHeaders["Cache-Control"] ?: return@mapNotNull null
        if (!entry.authHints.isNotEmpty() && !cacheControl.contains("public", ignoreCase = true)) {
            return@mapNotNull null
        }

        passiveFinding(
            category = "cache",
            severity = if (entry.authHints.isNotEmpty()) "medium" else "low",
            confidence = "low",
            historyRefs = listOf(entry.ref.ref),
            evidence = listOf("Response advertised `Cache-Control: $cacheControl`${if (entry.authHints.isNotEmpty()) " on an authenticated request" else ""}."),
            suggestedChecks = listOf("cache_poisoning_basic")
        )
    }
}

private fun findSecretAndDebugCandidates(entries: List<HistoryEntry>, profiles: Set<String>): List<PassiveFinding> {
    return entries.mapNotNull { entry ->
        val evidence = mutableListOf<String>()
        if ("debug" in profiles && stackTraceRegex.containsMatchIn(entry.responseBody)) {
            evidence += "Response body contains stack-trace or exception markers."
        }
        if ("secrets" in profiles && secretRegex.containsMatchIn(entry.responseBody)) {
            evidence += "Response body appears to contain credential-like material or bearer tokens."
        }

        if (evidence.isEmpty()) {
            return@mapNotNull null
        }

        passiveFinding(
            category = if (evidence.any { it.contains("stack", ignoreCase = true) || it.contains("exception", ignoreCase = true) }) "debug" else "secrets",
            severity = "medium",
            confidence = "medium",
            historyRefs = listOf(entry.ref.ref),
            evidence = evidence,
            suggestedChecks = emptyList()
        )
    }
}

private fun findSsrfCandidates(entries: List<HistoryEntry>): List<PassiveFinding> {
    return entries.mapNotNull { entry ->
        val ssrfParams = entry.parameters.filter {
            ssrfNameRegex.containsMatchIn(it.name) || it.value.startsWith("http://") || it.value.startsWith("https://")
        }
        if (ssrfParams.isEmpty()) {
            return@mapNotNull null
        }

        passiveFinding(
            category = "ssrf",
            severity = "low",
            confidence = "low",
            historyRefs = listOf(entry.ref.ref),
            evidence = listOf("Request contains URL-like parameters (${ssrfParams.map { it.name }.distinct().joinToString(", ")})."),
            suggestedChecks = listOf("ssrf_candidate")
        )
    }
}

private fun findWebSocketCandidates(entries: List<HistoryEntry>): List<PassiveFinding> {
    return entries.filter { it.requestHeaders["Upgrade"]?.equals("websocket", ignoreCase = true) == true }
        .map { entry ->
            passiveFinding(
                category = "websocket",
                severity = "info",
                confidence = "low",
                historyRefs = listOf(entry.ref.ref),
                evidence = listOf("Request upgraded to WebSocket and may warrant protocol-specific auth and message validation."),
                suggestedChecks = emptyList()
            )
        }
}

private fun generateIdorVariants(entry: HistoryEntry): List<VerificationVariant> {
    val variants = mutableListOf<VerificationVariant>()
    val firstNumeric = entry.parameters.firstOrNull { objectIdNameRegex.containsMatchIn(it.name) && numericValueRegex.matches(it.value) }
    if (firstNumeric != null) {
        val current = firstNumeric.value.toLongOrNull() ?: 0L
        listOf((current + 1).toString(), max(0, current - 1).toString()).distinct().forEachIndexed { idx, candidate ->
            val updated = entry.request.withParameter(HttpParameter.parameter(firstNumeric.name, candidate, HttpParameterType.valueOf(firstNumeric.type)))
            variants += updated.toVariant(
                entry,
                id = "idor-param-$idx",
                title = "Alternate object identifier in parameter `${firstNumeric.name}`",
                expectedSignal = "A similar 2xx response may indicate BOLA/IDOR."
            )
        }
    }

    val replacedPath = replaceFirstPathIdentifier(entry.path)
    if (replacedPath != null) {
        variants += entry.request.withPath(replacedPath).toVariant(
            entry,
            id = "idor-path",
            title = "Alternate object identifier in URL path",
            expectedSignal = "A similar successful response on a different object path may indicate BOLA/IDOR."
        )
    }
    return variants.distinctBy { it.rawRequest }
}

private fun generateMethodVariants(entry: HistoryEntry): List<VerificationVariant> {
    val method = entry.ref.method.uppercase()
    val candidates = when (method) {
        "GET" -> listOf("POST", "HEAD")
        "POST" -> listOf("GET", "PUT")
        "PUT" -> listOf("POST", "PATCH")
        "PATCH" -> listOf("PUT", "POST")
        "DELETE" -> listOf("POST", "GET")
        else -> listOf("GET", "POST")
    }.filter { it != method }

    return candidates.mapIndexed { idx, candidate ->
        entry.request.withMethod(candidate).toVariant(
            entry,
            id = "method-$idx",
            title = "Method tampering to $candidate",
            expectedSignal = "Unexpected success on alternate methods may indicate lax method enforcement."
        )
    }
}

private fun generateAuthDropVariants(entry: HistoryEntry): List<VerificationVariant> {
    val authHeaders = listOf("Authorization", "Cookie", "X-CSRF-Token", "X-XSRF-Token")
        .filter { entry.requestHeaders.keys.any { key -> key.equals(it, ignoreCase = true) } }
    if (authHeaders.isEmpty()) {
        return emptyList()
    }

    val variants = authHeaders.mapIndexed { idx, header ->
        entry.request.withRemovedHeader(header).toVariant(
            entry,
            id = "auth-drop-$idx",
            title = "Drop `$header` header",
            expectedSignal = "If the response stays successful and similar, auth enforcement may be weak."
        )
    }.toMutableList()

    if (authHeaders.size > 1) {
        val stripped = authHeaders.fold(entry.request) { req, header -> req.withRemovedHeader(header) }
        variants += stripped.toVariant(
            entry,
            id = "auth-drop-all",
            title = "Drop all obvious auth headers",
            expectedSignal = "A successful response without auth material is a strong bypass signal."
        )
    }

    return variants
}

private fun generateOriginVariants(entry: HistoryEntry): List<VerificationVariant> {
    return listOf(
        entry.request.withHeader("Origin", "https://evil.example.org").toVariant(
            entry,
            id = "origin-evil",
            title = "CORS probe with attacker Origin",
            expectedSignal = "Reflected ACAO or credentialed cross-origin success is interesting."
        ),
        entry.request.withHeader("Origin", "null").toVariant(
            entry,
            id = "origin-null",
            title = "CORS probe with `Origin: null`",
            expectedSignal = "Some apps trust `null` origin incorrectly."
        )
    )
}

private fun generateCacheVariants(entry: HistoryEntry): List<VerificationVariant> {
    return listOf(
        entry.request
            .withHeader("X-Forwarded-Host", "poison.example.org")
            .withHeader("X-Host", "poison.example.org")
            .toVariant(
                entry,
                id = "cache-poison-host",
                title = "Cache poisoning probe via forwarded host headers",
                expectedSignal = "Header reflection or altered absolute URLs can indicate poisoning risk."
            ),
        entry.request
            .withHeader("X-Original-URL", "/poisoned")
            .toVariant(
                entry,
                id = "cache-poison-path",
                title = "Cache poisoning probe via path override header",
                expectedSignal = "Unexpected path override behaviour may be cache-relevant."
            )
    )
}

private fun generateOpenRedirectVariants(entry: HistoryEntry): List<VerificationVariant> {
    val redirectParams = entry.parameters.filter { redirectNameRegex.containsMatchIn(it.name) }
    return redirectParams.mapIndexed { idx, param ->
        entry.request.withParameter(HttpParameter.parameter(param.name, "https://example.org/burpmcp", HttpParameterType.valueOf(param.type)))
            .toVariant(
                entry,
                id = "redirect-$idx",
                title = "Open redirect probe on `${param.name}`",
                expectedSignal = "Location or body reflection of the supplied URL may indicate an open redirect."
            )
    }
}

private fun generateSsrfVariants(entry: HistoryEntry, payloadValue: String?): List<VerificationVariant> {
    val targetValue = payloadValue ?: "http://{{collaborator}}/"
    val ssrfParams = entry.parameters.filter { ssrfNameRegex.containsMatchIn(it.name) || it.value.startsWith("http://") || it.value.startsWith("https://") }
    return ssrfParams.mapIndexed { idx, param ->
        entry.request.withParameter(HttpParameter.parameter(param.name, targetValue, HttpParameterType.valueOf(param.type)))
            .toVariant(
                entry,
                id = "ssrf-$idx",
                title = "SSRF probe on `${param.name}`",
                expectedSignal = "Use a Collaborator payload and then poll interactions to confirm server-side fetches."
            )
    }
}

private fun generateNumericBoundaryVariants(entry: HistoryEntry): List<VerificationVariant> {
    val numericParams = entry.parameters.filter { numericValueRegex.matches(it.value) }
    val candidateValues = listOf("0", "-1", "1", "999999999")
    return numericParams.take(2).flatMapIndexed { idx, param ->
        candidateValues.filter { it != param.value }.map { value ->
            entry.request.withParameter(HttpParameter.parameter(param.name, value, HttpParameterType.valueOf(param.type)))
                .toVariant(
                    entry,
                    id = "numeric-$idx-$value",
                    title = "Boundary probe `${param.name}=$value`",
                    expectedSignal = "Look for validation errors, auth edge cases or server exceptions."
                )
        }
    }
}

private fun replaceFirstPathIdentifier(path: String): String? {
    val parts = path.split('/').toMutableList()
    for (index in parts.indices) {
        val current = parts[index]
        when {
            numericValueRegex.matches(current) -> {
                val next = (current.toLongOrNull() ?: return null) + 1
                parts[index] = next.toString()
                return parts.joinToString("/")
            }

            uuidRegex.matches(current) -> {
                parts[index] = "11111111-1111-4111-8111-111111111111"
                return parts.joinToString("/")
            }
        }
    }
    return null
}

private fun HttpRequest.toVariant(
    entry: HistoryEntry,
    id: String,
    title: String,
    expectedSignal: String
): VerificationVariant {
    val mode = if (runCatching { httpVersion() }.getOrDefault("").contains("2")) HttpMode.HTTP_2 else HttpMode.HTTP_1
    return VerificationVariant(
        id = id,
        title = title,
        expectedSignal = expectedSignal,
        rawRequest = toString(),
        request = this,
        httpMode = mode,
        targetHost = refHost(),
        targetPort = refPort(),
        usesHttps = refSecure(),
        path = runCatching { path() }.getOrDefault(entry.path)
    )
}

private fun HttpRequest.refHost(): String = httpService().host()
private fun HttpRequest.refPort(): Int = httpService().port()
private fun HttpRequest.refSecure(): Boolean = httpService().secure()

private fun detectAuthHints(request: HttpRequest): Set<String> {
    val hints = mutableSetOf<String>()
    request.headerValue("Authorization")?.let { auth ->
        when {
            auth.startsWith("Bearer ", ignoreCase = true) -> hints += "authorization:bearer"
            auth.startsWith("Basic ", ignoreCase = true) -> hints += "authorization:basic"
            auth.isNotBlank() -> hints += "authorization"
        }
    }

    request.headerValue("Cookie")?.let { cookie ->
        if (cookie.contains("session", ignoreCase = true)) hints += "cookie:session"
        if (cookie.contains("auth", ignoreCase = true) || cookie.contains("token", ignoreCase = true)) hints += "cookie:auth"
    }

    listOf("X-CSRF-Token", "X-XSRF-Token", "X-Api-Key").forEach { header ->
        if (request.hasHeader(header)) {
            hints += header.lowercase()
        }
    }

    return hints
}

private fun normalizeProfiles(requestedProfiles: List<String>): Set<String> {
    val defaults = setOf("auth", "idor", "input", "cors", "cache", "secrets", "debug", "ssrf", "websocket")
    if (requestedProfiles.isEmpty()) {
        return defaults
    }

    return requestedProfiles.map { it.lowercase() }.filter { it in defaults }.toSet().ifEmpty { defaults }
}

private fun passiveFinding(
    category: String,
    severity: String,
    confidence: String,
    historyRefs: List<String>,
    evidence: List<String>,
    suggestedChecks: List<String>
): PassiveFinding {
    val findingId = buildHistoryRef(category, historyRefs.joinToString(","), severity.hashCode(), evidence.joinToString("\n"))
        .take(16)
    return PassiveFinding(
        findingId = findingId,
        category = category,
        severity = severity,
        confidence = confidence,
        historyRefs = historyRefs.distinct(),
        evidence = evidence,
        whyItMatters = when (category) {
            "idor" -> "Object reference variance in similar requests often translates into missing authorization checks."
            "auth" -> "Auth and session controls are high-impact and small differentials can reveal bypasses."
            "cors" -> "Misconfigured CORS can expose authenticated data cross-origin."
            "cache" -> "Cacheable sensitive responses or host header reflection can lead to cache poisoning or data exposure."
            "debug" -> "Debug traces leak internals and often accelerate exploitation."
            "secrets" -> "Credential material or tokens in responses can lead to immediate compromise."
            "ssrf" -> "URL-like inputs often deserve server-side fetch validation."
            else -> "The endpoint exposes behaviour that is worth manual validation during triage."
        },
        suggestedChecks = suggestedChecks.distinct()
    )
}

private fun severityRank(severity: String): Int = when (severity.lowercase()) {
    "high" -> 4
    "medium" -> 3
    "low" -> 2
    "info" -> 1
    else -> 0
}

private fun tokenSimilarity(left: String, right: String): Double {
    if (left.isBlank() && right.isBlank()) return 1.0
    val leftTokens = left.lowercase().split(Regex("[^a-z0-9]+")).filter { it.isNotBlank() }.toSet()
    val rightTokens = right.lowercase().split(Regex("[^a-z0-9]+")).filter { it.isNotBlank() }.toSet()
    if (leftTokens.isEmpty() || rightTokens.isEmpty()) {
        val maxLength = max(left.length, right.length).coerceAtLeast(1)
        return 1.0 - (abs(left.length - right.length).toDouble() / maxLength)
    }

    val intersection = leftTokens.intersect(rightTokens).size.toDouble()
    val union = leftTokens.union(rightTokens).size.toDouble().coerceAtLeast(1.0)
    return min(1.0, max(0.0, intersection / union))
}

@Serializable
data class HistorySummaryResult(
    val grouped: Boolean,
    val itemCount: Int,
    val endpointCount: Int,
    val endpoints: List<EndpointSummary>,
    val items: List<HistoryItemSummary>
)

@Serializable
data class HistoryAnalysisResult(
    val itemCount: Int,
    val consideredProfiles: List<String>,
    val findings: List<PassiveFinding>
)

@Serializable
data class HistoryRef(
    val ref: String,
    val method: String,
    val url: String,
    val host: String,
    val inScope: Boolean,
    val statusCode: Int? = null,
    val note: String? = null
)

@Serializable
data class EndpointSummary(
    val host: String,
    val route: String,
    val methods: List<String>,
    val frequency: Int,
    val authHints: List<String>,
    val requestContentTypes: List<String>,
    val responseContentTypes: List<String>,
    val statusCodes: Map<Int, Int>,
    val parameters: List<EndpointParameterSummary>,
    val sampleRefs: List<String>
)

@Serializable
data class EndpointParameterSummary(
    val name: String,
    val types: List<String>,
    val sampleValues: List<String>,
    val distinctValueCount: Int,
    val looksSensitive: Boolean,
    val looksNumeric: Boolean
)

@Serializable
data class HistoryItemSummary(
    val ref: HistoryRef,
    val route: String,
    val authHints: List<String>,
    val requestContentType: String? = null,
    val responseContentType: String? = null,
    val parameterNames: List<String>
)

@Serializable
data class PassiveFinding(
    val findingId: String,
    val category: String,
    val severity: String,
    val confidence: String,
    val historyRefs: List<String>,
    val evidence: List<String>,
    val whyItMatters: String,
    val suggestedChecks: List<String>
)

@Serializable
data class VerificationPlan(
    val historyRef: String,
    val checkType: String,
    val variants: List<VerificationVariantPreview>
)

@Serializable
data class VerificationVariantPreview(
    val id: String,
    val title: String,
    val expectedSignal: String,
    val rawRequest: String
)

@Serializable
data class VerificationExecutionResult(
    val historyRef: String,
    val checkType: String,
    val safeMode: Boolean,
    val previewOnly: Boolean,
    val baseline: ResponseSnapshot?,
    val variants: List<ExecutedVerificationVariant>,
    val conclusion: String,
    val followUp: String
)

@Serializable
data class ResponseSnapshot(
    val statusCode: Int,
    val reasonPhrase: String?,
    val bodyLength: Int,
    val location: String?,
    val cacheControl: String?,
    val contentType: String?,
    val bodyPreview: String,
    val similarityHash: String
)

@Serializable
data class ExecutedVerificationVariant(
    val id: String,
    val title: String,
    val expectedSignal: String,
    val requestPreview: String,
    val response: ResponseSnapshot?,
    val observations: List<String>
)

@Serializable
data class FindingBundle(
    val finding: PassiveFinding,
    val supportingRequests: List<HistoryItemSummary>,
    val suggestedVerificationRequests: List<VerificationVariantPreview>
)

internal data class HistoryEntry(
    val ref: HistoryRef,
    val request: HttpRequest,
    val response: HttpResponse?,
    val path: String,
    val query: String?,
    val normalizedRoute: String,
    val authHints: List<String>,
    val requestHeaders: Map<String, String>,
    val responseHeaders: Map<String, String>,
    val requestBody: String,
    val responseBody: String,
    val responseMimeType: String?,
    val responseBodyLength: Int,
    val parameters: List<ObservedParameter>
) {
    fun toItemSummary(): HistoryItemSummary {
        return HistoryItemSummary(
            ref = ref,
            route = normalizedRoute,
            authHints = authHints,
            requestContentType = requestHeaders["Content-Type"],
            responseContentType = responseMimeType ?: responseHeaders["Content-Type"],
            parameterNames = parameters.map { it.name }.distinct().sorted()
        )
    }
}

internal data class ObservedParameter(
    val name: String,
    val value: String,
    val type: String
)

internal data class VerificationVariant(
    val id: String,
    val title: String,
    val expectedSignal: String,
    val rawRequest: String,
    val request: HttpRequest,
    val httpMode: HttpMode,
    val targetHost: String,
    val targetPort: Int,
    val usesHttps: Boolean,
    val path: String
) {
    fun preview(): VerificationVariantPreview = VerificationVariantPreview(
        id = id,
        title = title,
        expectedSignal = expectedSignal,
        rawRequest = rawRequest
    )
}
