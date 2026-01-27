# Fishial.AI V2 API Specification & Driver Implementation Guide

**Version:** 2.1 (Strict Mode)  
**Target Audience:** Autonomous Agents, LLMs, and Driver Developers  
**Purpose:** To define the strict protocol, error handling, and state management required to build a robust, production-grade API client for the Fishial.AI V2 ecosystem.

---

## 1. Environment Configuration

The driver must support switching between environments via configuration (constructor args or environment variables).

| Environment | Base URL | Usage |
| :--- | :--- | :--- |
| **Production** | `https://api-recognition.fishial.ai` | Live traffic. Strict rate limits. |
| **Staging** | `https://api-recognition-stage.fishial.ai` | Integration testing. |

---

## 2. Authentication Protocol (Stateful)

The API uses **OAuth2 Client Credentials** flow. The driver **MUST** manage the token lifecycle automatically.

### **2.1 Token Acquisition**
* **Endpoint:** `/v2/auth`
* **Method:** `POST`
* **Headers:** `Content-Type: application/json`
* **Payload Schema:**
    ```json
    {
      "client_id": "string (Required)",
      "client_secret": "string (Required)"
    }
    ```

### **2.2 Token Lifecycle Management (Driver Requirement)**
The driver **MUST** implement the following logic:
1.  **Storage:** Store the `access_token` and `expires_in` timestamp in memory.
2.  **Pre-emptive Refresh:** Schedule a refresh 60 seconds *before* the token expires.
3.  **Reactive Refresh (401 Retry):** If any API call returns `401 Unauthorized`:
    * Immediately attempt to fetch a new token.
    * If successful, replay the original failed request with the new token.
    * If auth fails again, raise a critical `AuthenticationException`.

---

## 3. Resource: Image Recognition

### **3.1 Specification**
* **Endpoint:** `/v2/recognize`
* **Method:** `POST`
* **Content-Type:** `application/octet-stream` (Do NOT use `multipart/form-data`)
* **Payload:** Raw binary bytes of the image file.

### **3.2 Supported Binary Formats**
Driver must validate file signatures (Magic Bytes) or MIME types before sending.
* **Allowed:** `AVIF`, `GIF`, `HEIC`, `HEIF`, `JPEG`, `JPEG 2000` (.jp2), `JPEG XL` (.jxl), `PNG`, `TIFF`, `WebP`.
* **Rejected:** `BMP`, `SVG`, `PDF`, `EXE`.

### **3.3 Header Schema**
The driver must sanitize all headers to ensure they are strictly **ASCII (7-bit)**.

| Header Name | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `Authorization` | String | `Bearer <TOKEN>` | The active access token. |
| `Fishial-Fish-Detection-Threshold` | Float | `0.3` to `1.0` | Confidence cutoff. Default: `0.3`. |
| `Fishial-Location-Lat-Lon` | String | `Lat, Lon` | Decimal degrees. e.g., `-55.2, -67.8`. |
| `Fishial-Image-Tags` | String | ASCII Only | Comma-separated metadata. |
| `Fishial-Image-License-Code` | String | Enum | `CC-BY-4.0`, `CC0-1.0`, etc. |
| `Fishial-Debug:` |String |`On`| additional metadata|

### **3.4 Response Schema (JSON)**
```json
{
  "queryToken": "string (Critical for Feedback Loop)",
  "mediaId": "string (UUID)",
  "objects": [
    {
      "bbox": [100, 150, 400, 300],
      "species": [
        {
          "name": "Micropterus salmoides",
          "certainty": 0.95
        }
      ]
    }
  ]
}
```
---

## 4. Resource: User Feedback (The "Loop")

The feedback loop is critical for model improvement. The driver **MUST** implement strict client-side validation to ensure data quality before hitting the network.

### **4.1 Specification**
* **Endpoint:** `/v2/comment`
* **Method:** `POST`
* **Content-Type:** `application/json`
* **Auth:** Required (Bearer Token)

### **4.2 Payload Schema & Driver Validation Logic**
The driver **MUST** validate these constraints locally and raise a `ClientValidationException` if failed.

| Field | Type | Driver Validation Rule | Description |
| :--- | :--- | :--- | :--- |
| `queryToken` | String | **Required.** Must be non-empty. | The signed opaque string received in the `/v2/recognize` response. |
| `opinion` | String | **Required.** Enum: `['Agree', 'Disagree', 'Unknown']`. | The user's verdict on the prediction. |
| `objectIndex` | Integer | **Optional.** Must be `>= 0`. | The index of the specific fish in the `objects` array being critiqued. |
| `suggestedSpeciesName` | String | **Conditional.** If `opinion` is `'Disagree'`, this field is **REQUIRED**. | The correct species name (Scientific or Common). |

---

## 5. Resiliency & Error Handling Standards

A "bullet-proof" driver **MUST** handle the following HTTP codes exactly as described.

| HTTP Code | Exception Type | Cause | Driver Action |
| :--- | :--- | :--- | :--- |
| **200** | `None` | Success. | Return parsed JSON object. |
| **400** | `ValidationException` | Bad Request (Headers, Malformed JSON, Empty File). | **Fatal.** Log error message. Do not retry. |
| **401** | `AuthException` | Token Expired or Invalid. | **Recoverable.** Trigger "Reactive Refresh" logic. Retry request once. |
| **403** | `PermissionException` | Token valid but lacks scope, or `queryToken` tampered. | **Fatal.** Do not retry. |
| **404** | `NotFoundException` | Endpoint does not exist. | **Fatal.** Check URL configuration. |
| **405** | `MethodNotAllowed` | Wrong HTTP Verb (e.g., GET vs POST). | **Fatal.** Check driver implementation. |
| **408** | `TimeoutException` | Slowloris or Network Stall. | **Retry.** Treat as network error. |
| **413** | `PayloadTooLarge` | Image exceeds server limit (>50MB). | **Fatal.** Do not retry. |
| **415** | `UnsupportedMedia` | Invalid File Type (e.g., BMP). | **Fatal.** Do not retry. |
| **429** | `RateLimitException` | Too Many Requests. | **Backoff.** Read `Retry-After` header. Sleep for that duration + jitter. Retry. |
| **431** | `HeaderTooLarge` | Header Buffer Overflow. | **Fatal.** Do not retry. |
| **500** | `ServerException` | Internal Server Crash. | **Retry.** Retry with backoff. |
| **503** | `ServiceUnavailable` | Maintenance / Model Offline. | **Backoff.** Implement Exponential Backoff (base 5s, max 60s). |

---

## 6. Driver Architecture Guidelines

Any AI or developer generating a client library for this API **MUST** adhere to these architectural patterns:

1.  **Singleton Session:** Use a single persistent HTTP session (e.g., `requests.Session` in Python) to enable **Connection Pooling** and **Keep-Alive**. Do not open a new socket for every request.
2.  **Thread Safety:** The token storage must be thread-safe (e.g., use a Lock/Mutex) to prevent race conditions during token refresh in multi-threaded environments.
3.  **Sanitization:** Automatically strip non-ASCII characters from headers before sending. If a user inputs "Fishing 🎣", the driver should either strip the emoji or raise a `ValueError` locally before making the network call.
4.  **Timeouts:** Enforce explicit timeouts.
    * **Connect Timeout:** 5 seconds (Fail fast if DNS/Network is down).
    * **Read Timeout:** 60 seconds (Model inference is heavy).
5.  **Logging & Security:**
    * **Log:** URLs, Status Codes, Latency, Retry attempts.
    * **Redact:** Never log the `client_secret` or the full `access_token` (log only the checksum/last 4 chars).

---

## 7. Retry Policy (Exponential Backoff)

For HTTP `408`, `429`, `500`, `502`, `503`, and `504`, the driver must implement the following algorithm:

1.  **Attempt 1:** Request fails.
2.  **Wait:** `min(base_delay * (2 ^ attempt), max_delay) + jitter`
    * `base_delay`: 2 seconds
    * `max_delay`: 60 seconds
    * `jitter`: Random(0, 1000ms)
3.  **Retry:** Up to `MAX_RETRIES` (default 3).
4.  **Give Up:** Raise specific exception after max retries exhausted.
