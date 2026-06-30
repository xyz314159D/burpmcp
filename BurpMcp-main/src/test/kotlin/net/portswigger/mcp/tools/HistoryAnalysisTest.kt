package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

class HistoryAnalysisTest {

    @Test
    fun `normalizeRoute should replace common identifier segments`() {
        assertEquals("/api/users/{id}/orders/{uuid}", normalizeRoute("/api/users/123/orders/550e8400-e29b-41d4-a716-446655440000"))
        assertEquals("/files/{token}/download", normalizeRoute("/files/abcdef0123456789abcdef0123456789/download"))
        assertEquals("/", normalizeRoute("/"))
    }

    @Test
    fun `buildHistoryRef should be deterministic and content sensitive`() {
        val left = buildHistoryRef("GET", "https://example.com/api/1", 200, "GET /api/1 HTTP/1.1")
        val leftAgain = buildHistoryRef("GET", "https://example.com/api/1", 200, "GET /api/1 HTTP/1.1")
        val right = buildHistoryRef("GET", "https://example.com/api/2", 200, "GET /api/2 HTTP/1.1")

        assertEquals(left, leftAgain)
        assertNotEquals(left, right)
    }
}
