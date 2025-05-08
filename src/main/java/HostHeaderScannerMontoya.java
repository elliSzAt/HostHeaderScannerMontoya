import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicLong;

public class HostHeaderScannerMontoya implements BurpExtension, HttpHandler {
    private MontoyaApi api;
    private Logging logging;
    private final Set<String> testedRequests = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> responseTimes = new ConcurrentHashMap<>();
    private static final long RATE_LIMIT_MS = 100;
    private static final long CACHE_THRESHOLD_MS = 50; // Threshold for cache detection
    private final AtomicLong lastRequestTime = new AtomicLong(0);

    // Common web frameworks and their specific headers
    private static final Map<String, List<String>> FRAMEWORK_HEADERS = Map.of(
        "WordPress", Arrays.asList("X-Powered-By", "X-WP-*"),
        "Laravel", Arrays.asList("X-Powered-By", "X-Laravel-*"),
        "Django", Arrays.asList("X-Powered-By", "X-Django-*"),
        "Rails", Arrays.asList("X-Powered-By", "X-Rails-*")
    );

    private final List<String> staticPayloads = Arrays.asList(
        // Basic payloads
        "evil.com", "attacker.com", "cachepoison.xyz", "localhost",
        // SSRF payloads
        "127.0.0.1", "0.0.0.0", "::1", "localhost",
        // Cache poisoning payloads
        "cache.evil.com", "cdn.evil.com", "static.evil.com",
        // Protocol payloads
        "http://evil.com", "https://evil.com", "ftp://evil.com",
        // Port payloads
        "evil.com:80", "evil.com:443", "evil.com:8080",
        // Special characters
        "evil.com/", "evil.com?", "evil.com#", "evil.com@",
        // Null byte injection
        "evil.com%00", "evil.com\u0000",
        // Framework specific payloads
        "wordpress.evil.com", "wp-admin.evil.com",
        "laravel.evil.com", "django.evil.com",
        "rails.evil.com"
    );

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        this.logging = api.logging();
        api.extension().setName("Advanced Host Header Scanner");
        logging.logToOutput("Extension loaded: Advanced Host Header Scanner");
        api.http().registerHttpHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        // Rate limiting with atomic operations
        long currentTime = System.currentTimeMillis();
        long lastTime = lastRequestTime.get();
        long timeToWait = RATE_LIMIT_MS - (currentTime - lastTime);
        
        if (timeToWait > 0) {
            try {
                Thread.sleep(timeToWait);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        lastRequestTime.set(System.currentTimeMillis());

        // Skip if already tested
        String requestKey = request.url() + request.method();
        if (testedRequests.contains(requestKey)) {
            return RequestToBeSentAction.continueWith(request);
        }
        testedRequests.add(requestKey);

        String originalHost = request.headerValue("Host");
        if (originalHost == null) {
            originalHost = "example.com";
        }

        // Detect framework
        String framework = detectFramework(request);
        
        // Generate dynamic payloads based on context
        List<String> dynamicPayloads = generateDynamicPayloads(originalHost, framework);

        // Combine all payloads
        List<String> allPayloads = new ArrayList<>();
        allPayloads.addAll(staticPayloads);
        allPayloads.addAll(dynamicPayloads);

        // Get random payload
        String payload = allPayloads.get(new Random().nextInt(allPayloads.size()));

        // Inject headers
        Map<String, String> injectedHeaders = new LinkedHashMap<>();
        injectedHeaders.put("Host", payload);
        injectedHeaders.put("X-Forwarded-Host", payload);
        injectedHeaders.put("X-Host", payload);
        injectedHeaders.put("X-Forwarded-Server", payload);
        injectedHeaders.put("X-Original-URL", payload);
        injectedHeaders.put("X-Rewrite-URL", payload);
        
        // Add framework specific headers
        if (framework != null) {
            for (String header : FRAMEWORK_HEADERS.get(framework)) {
                injectedHeaders.put(header, payload);
            }
        }

        HttpRequest modified = request;
        for (Map.Entry<String, String> entry : injectedHeaders.entrySet()) {
            modified = modified.withUpdatedHeader(entry.getKey(), entry.getValue());
        }

        // Store request time for cache detection
        responseTimes.put(requestKey, System.currentTimeMillis());

        logging.logToOutput("Injected headers with payload: " + payload + " → " + request.method() + " " + request.url());
        return RequestToBeSentAction.continueWith(modified);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        HttpRequest request = responseReceived.initiatingRequest();
        HttpResponse response = responseReceived;
        String body = response.bodyToString();
        int statusCode = response.statusCode();
        String requestKey = request.url() + request.method();

        // Calculate response time
        long responseTime = System.currentTimeMillis() - responseTimes.getOrDefault(requestKey, 0L);
        boolean isCacheHit = responseTime < CACHE_THRESHOLD_MS;

        boolean payloadFound = false;
        String matchedPayload = null;
        boolean isRedirect = statusCode >= 300 && statusCode < 400;
        boolean isSSRF = false;
        boolean isCachePoisoning = false;
        List<String> vulnerabilityDetails = new ArrayList<>();

        // Check for SSRF indicators
        if (body.contains("127.0.0.1") || body.contains("localhost") || 
            body.contains("0.0.0.0") || body.contains("::1")) {
            isSSRF = true;
            vulnerabilityDetails.add("SSRF: Local IP address found in response");
        }

        // Check cache headers
        String cacheHeader = response.headerValue("X-Cache");
        if (cacheHeader != null && cacheHeader.toLowerCase().contains("hit")) {
            isCachePoisoning = true;
            vulnerabilityDetails.add("Cache Poisoning: Cache hit detected");
        }

        // Check for framework specific indicators
        String framework = detectFramework(request);
        List<String> allPayloads = new ArrayList<>(staticPayloads);
        if (framework != null) {
            allPayloads.addAll(generateDynamicPayloads(request.headerValue("Host"), framework));
        }

        // Check payload in body and headers
        for (String payload : allPayloads) {
            if (body.contains(payload)) {
                payloadFound = true;
                matchedPayload = payload;
                vulnerabilityDetails.add("Host Header Injection: Payload found in response body");
                break;
            }
        }

        // Check response headers
        String[] headersToCheck = {
            "Location", "Content-Location", "X-Host", "X-Forwarded-Host",
            "X-Cache", "X-Cache-Hit", "X-Original-URL", "X-Rewrite-URL"
        };

        for (String header : headersToCheck) {
            String value = response.headerValue(header);
            if (value != null) {
                for (String payload : allPayloads) {
                    if (value.contains(payload)) {
                        payloadFound = true;
                        matchedPayload = payload;
                        vulnerabilityDetails.add("Host Header Injection: Payload found in header '" + header + "'");
                        break;
                    }
                }
            }
        }

        // Analyze and log results
        if (!vulnerabilityDetails.isEmpty()) {
            StringBuilder report = new StringBuilder();
            report.append("\n=== VULNERABILITY DETECTED ===\n");
            report.append("URL: ").append(request.url()).append("\n");
            report.append("Method: ").append(request.method()).append("\n");
            report.append("Status Code: ").append(statusCode).append("\n");
            
            if (framework != null) {
                report.append("Framework: ").append(framework).append("\n");
            }
            
            if (matchedPayload != null) {
                report.append("Matched Payload: ").append(matchedPayload).append("\n");
            }
            
            report.append("\nVulnerability Details:\n");
            for (String detail : vulnerabilityDetails) {
                report.append("- ").append(detail).append("\n");
            }
            
            report.append("\nResponse Headers:\n");
            for (String header : headersToCheck) {
                String value = response.headerValue(header);
                if (value != null) {
                    report.append(header).append(": ").append(value).append("\n");
                }
            }
            
            report.append("\nResponse Time: ").append(responseTime).append("ms\n");
            if (isCacheHit) {
                report.append("Cache Hit Detected\n");
            }
            
            report.append("===========================\n");
            
            logging.logToError(report.toString());
        } else {
            logging.logToOutput("No vulnerabilities detected at: " + request.url() + " | Status: " + statusCode);
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private String detectFramework(HttpRequest request) {
        String body = request.bodyToString();
        String headers = request.headers().toString();

        if (body.contains("wp-") || headers.contains("wp-")) {
            return "WordPress";
        } else if (body.contains("laravel") || headers.contains("laravel")) {
            return "Laravel";
        } else if (body.contains("django") || headers.contains("django")) {
            return "Django";
        } else if (body.contains("rails") || headers.contains("rails")) {
            return "Rails";
        }
        return null;
    }

    private List<String> generateDynamicPayloads(String originalHost, String framework) {
        List<String> payloads = new ArrayList<>();
        
        // Basic dynamic payloads
        payloads.add("evil." + originalHost);
        payloads.add(originalHost + ".attacker.com");
        payloads.add(originalHost + "/evil");
        payloads.add(originalHost + ":80");
        payloads.add(originalHost + ":443");
        payloads.add("http://" + originalHost);
        payloads.add("https://" + originalHost);

        // Framework specific payloads
        if (framework != null) {
            switch (framework) {
                case "WordPress":
                    payloads.add("wp-admin." + originalHost);
                    payloads.add(originalHost + "/wp-admin");
                    break;
                case "Laravel":
                    payloads.add("admin." + originalHost);
                    payloads.add(originalHost + "/admin");
                    break;
                case "Django":
                    payloads.add("admin." + originalHost);
                    payloads.add(originalHost + "/admin");
                    break;
                case "Rails":
                    payloads.add("admin." + originalHost);
                    payloads.add(originalHost + "/admin");
                    break;
            }
        }

        return payloads;
    }
}

