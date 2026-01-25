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
