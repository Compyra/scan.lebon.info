// Network Scanner Script
let scanActive = false;
let scannedCount = 0;
let autoRepeatInterval = null;
let hostsMap = new Map();
let rangeScanActive = false;
let responseCodesVisible = false;

// Detect if we're running on HTTPS (which blocks HTTP requests due to mixed content)
const isHttpsPage = window.location.protocol === 'https:';
const canScanHttp = !isHttpsPage;

const RANGE_SCAN_BATCH_SIZE = 5;
const SCAN_BATCH_SIZE = 5;
const RANGE_SCAN_TIMEOUT = 2000;

const RANGE_SCAN_CONFIG = {
    '192.168': {
        label: '192.168.0.0/16',
        start: 0,
        end: 255,
        buildAddress: segment => `192.168.${segment}.1`
    },
    '172.16': {
        label: '172.16.0.0/12',
        start: 16,
        end: 31,
        buildAddress: segment => `172.${segment}.0.1`
    },
    '10.0': {
        label: '10.0.0.0/8',
        start: 0,
        end: 255,
        buildAddress: segment => `10.${segment}.0.1`
    }
};

const RANGE_SCAN_ORDER = ['192.168', '172.16', '10.0'];

// Scan IP ranges for .1 addresses
async function scanIPRange(baseIP) {
    if (rangeScanActive) {
        alert('A range scan is already in progress. Please wait.');
        return;
    }

    const config = RANGE_SCAN_CONFIG[baseIP];
    if (!config) {
        alert('Unsupported range selection.');
        return;
    }

    rangeScanActive = true;
    const resultsDiv = document.getElementById('rangeResults');
    const buttons = document.querySelectorAll('.btn-range');

    // Disable all buttons during scan
    buttons.forEach(btn => btn.disabled = true);

    resultsDiv.innerHTML = '<p class="loading">Scanning for gateway addresses...</p>';
    renderRangeTimeEstimates(baseIP);

    const { start: rangeStart, end: rangeEnd, buildAddress } = config;
    const foundIPs = [];
    const batchSize = RANGE_SCAN_BATCH_SIZE; // Reduced batch size for more reliable scanning
    
    for (let i = rangeStart; i <= rangeEnd; i += batchSize) {
        if (!rangeScanActive) break; // Allow cancellation
        
        const batch = [];
        const batchEnd = Math.min(i + batchSize - 1, rangeEnd);
        
        for (let j = i; j <= batchEnd; j++) {
            const ip = buildAddress(j);
            batch.push(scanIP(ip, RANGE_SCAN_TIMEOUT)); // Increased timeout for gateway detection
        }
        
        const results = await Promise.all(batch);
        
        results.forEach(result => {
            if (result.active) {
                foundIPs.push(result.ip);
            }
        });
        
        // Update progress
        const progress = Math.round(((i - rangeStart + batchSize) / (rangeEnd - rangeStart + 1)) * 100);
        resultsDiv.innerHTML = `<p class="loading">Scanning... ${Math.min(progress, 100)}% (Found: ${foundIPs.length})</p>`;
    }
    
    // Display results
    if (foundIPs.length > 0) {
        resultsDiv.innerHTML = `
            <p class="success">Found ${foundIPs.length} active gateway(s):</p>
            <div class="found-ips">
                ${foundIPs.map(ip => {
                    const networkBase = ip.substring(0, ip.lastIndexOf('.'));
                    return `
                        <div class="found-ip-item">
                            <span class="ip-address">${ip}</span>
                            <button class="btn-use" onclick="useNetwork('${networkBase}')">Use ${networkBase}</button>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    } else {
        resultsDiv.innerHTML = '<p class="warning">No active gateways found in this range.</p>';
    }
    
    // Re-enable buttons
    buttons.forEach(btn => btn.disabled = false);
    rangeScanActive = false;
    renderRangeTimeEstimates(baseIP);
}

function useNetwork(networkBase) {
    document.getElementById('networkBase').value = networkBase;
    // Optionally scroll to the scan section
    document.querySelector('.section:nth-child(2)').scrollIntoView({ behavior: 'smooth' });
    updateTimeEstimate();
}

// Scan a single IP address
async function scanIP(ip, timeout) {
    const startTime = Date.now();
    
    // Try HTTPS first, then HTTP
    const protocols = ['https', 'http'];
    
    for (const protocol of protocols) {
        const protocolStartTime = Date.now();
        let timeoutId;
        try {
            const controller = new AbortController();
            timeoutId = setTimeout(() => controller.abort(), timeout);
            
            // Start the fetch request
            const fetchPromise = fetch(`${protocol}://${ip}/`, {
                method: 'HEAD',
                mode: 'no-cors',
                cache: 'no-cache',
                signal: controller.signal
            });
            
            // Add minimum wait time to ensure we don't return too quickly
            const minWaitPromise = new Promise(resolve => setTimeout(resolve, 50));
            
            // Wait for both the fetch and minimum wait time
            const [response] = await Promise.all([fetchPromise, minWaitPromise]);
            
            clearTimeout(timeoutId);
            const responseTime = Date.now() - startTime;
            
            // If we got any response (even opaque), the host is active
            console.log(`${ip} is active via ${protocol}, responseTime: ${responseTime}ms`);
            return { ip, active: true, responseTime, protocol };
        } catch (error) {
            if (timeoutId) clearTimeout(timeoutId);
            const protocolElapsed = Date.now() - protocolStartTime;
            
            // Wait minimum time even on error to avoid false negatives
            if (protocolElapsed < 50) {
                await new Promise(resolve => setTimeout(resolve, 50 - protocolElapsed));
            }
            
            // Log the error for debugging
            console.log(`${ip} ${protocol} failed: ${error.name} after ${protocolElapsed}ms`);
            
            // Continue to next protocol or return inactive
            if (error.name === 'AbortError') {
                // Timeout - try next protocol
                continue;
            }
            // Network errors - try next protocol
            continue;
        }
    }
    
    // If both protocols failed, host is inactive
    console.log(`${ip} is inactive (both protocols failed)`);
    return { ip, active: false };
}

// Try to get HTTP status and headers with detailed error detection
async function getHostInfo(ip) {
    const info = {
        httpStatus: null,
        httpsStatus: null,
        headers: {},
        ports: {
            http: false,
            https: false
        },
        httpError: null,
        httpsError: null,
        httpDetails: null,
        httpsDetails: null
    };

    // Helper function to analyze error and provide detailed information
    const analyzeError = (err, protocol, ip, response = null, gotOpaqueResponse = false, responseTime = 0) => {
        let errorType = 'Unknown Error';
        let details = null;
        
        // If we got an opaque response, it means server responded but CORS blocked
        if (gotOpaqueResponse) {
            errorType = 'CORS_BLOCKED';
            details = 'Server responded (status unknown: 200/302/etc), CORS blocks details';
            return { errorType, details };
        }
        
        if (err) {
            // AbortError = timeout
            if (err.name === 'AbortError') {
                errorType = 'ERR_CONNECTION_TIMED_OUT';
                details = `Connection timed out after 3000ms`;
            }
            // TypeError often indicates network-level issues
            else if (err.name === 'TypeError') {
                const msg = err.message || '';
                
                if (msg.includes('Failed to fetch')) {
                    // Use timing to distinguish between connection refused and SSL errors
                    // Connection refused: very fast (< 100ms)
                    // SSL errors: slower (> 100ms) as handshake is attempted
                    
                    if (protocol === 'https' && responseTime > 100) {
                        // Likely SSL/certificate error (handshake attempted but failed)
                        errorType = 'ERR_SSL_PROTOCOL_ERROR';
                        details = 'SSL/TLS handshake failed or certificate invalid';
                    } else if (responseTime < 100) {
                        // Very fast failure = connection refused
                        errorType = 'ERR_CONNECTION_REFUSED';
                        details = 'Connection refused or port not listening';
                    } else {
                        // Uncertain
                        if (protocol === 'https') {
                            errorType = 'ERR_FAILED';
                            details = 'Connection failed (SSL error or connection refused)';
                        } else {
                            errorType = 'ERR_CONNECTION_REFUSED';
                            details = 'Connection refused or network unreachable';
                        }
                    }
                } else {
                    errorType = 'TypeError';
                    details = msg;
                }
            }
            else {
                errorType = err.name || 'ERR_FAILED';
                details = err.message || 'Request failed';
            }
        }
        
        // If we got a response, analyze it
        if (response) {
            if (response.type === 'opaque') {
                errorType = 'CORS_BLOCKED';
                details = 'Server responded (status unknown: 200/302/etc), CORS blocks details';
            } else if (response.status) {
                details = `HTTP ${response.status} (${response.statusText || 'OK'})`;
            }
        }
        
        return { errorType, details };
    };

    // Check HTTP port (80) - skip if on HTTPS page (mixed content blocked)
    const httpResult = await (async () => {
        // If we're on HTTPS, browser will block HTTP requests (mixed content)
        if (!canScanHttp) {
            return {
                accessible: false,
                error: 'MIXED_CONTENT_BLOCKED',
                details: 'HTTP blocked by browser (running on HTTPS page)'
            };
        }
        
        const startTime = Date.now();
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            let corsError = null;
            let gotOpaqueResponse = false;
            
            // Try CORS mode first
            const httpResponse = await fetch(`http://${ip}/`, {
                method: 'HEAD',
                mode: 'cors',
                cache: 'no-cache',
                signal: controller.signal
            }).catch(async (err) => {
                corsError = err;
                // Try no-cors mode
                try {
                    const noCorsResponse = await fetch(`http://${ip}/`, {
                        method: 'GET',
                        mode: 'no-cors',
                        cache: 'no-cache',
                        signal: controller.signal
                    });
                    if (noCorsResponse && noCorsResponse.type === 'opaque') {
                        gotOpaqueResponse = true;
                    }
                    return noCorsResponse;
                } catch (fallbackErr) {
                    throw corsError; // Use original error
                }
            });
            
            clearTimeout(timeoutId);
            const responseTime = Date.now() - startTime;
            
            if (httpResponse) {
                if (httpResponse.type === 'opaque' || gotOpaqueResponse) {
                    // Server responded but CORS blocked - could be 200, 302, etc.
                    return {
                        accessible: true,
                        status: 'CORS Blocked',
                        // error: 'CORS_BLOCKED',
                        details: 'Server responded (status could be 200/302/etc), CORS blocks details'
                    };
                } else {
                    // Full response received
                    const headerKeys = ['server', 'content-type', 'x-powered-by', 'location'];
                    const headers = {};
                    headerKeys.forEach(key => {
                        const value = httpResponse.headers.get(key);
                        if (value) headers[key] = value;
                    });
                    
                    return {
                        accessible: true,
                        status: httpResponse.status,
                        statusText: httpResponse.statusText,
                        headers: headers
                    };
                }
            }
        } catch (e) {
            const responseTime = Date.now() - startTime;
            const analysis = analyzeError(e, 'http', ip, null, false, responseTime);
            return {
                accessible: false,
                error: analysis.errorType,
                details: analysis.details
            };
        }
    })();

    console.log(`${ip} HTTP check result:`, httpResult);
    if (httpResult.accessible) {
        info.ports.http = true;
        info.httpStatus = httpResult.status;
        if (httpResult.headers) {
            Object.assign(info.headers, httpResult.headers);
        }
        if (httpResult.error) {
            info.httpError = httpResult.error;
            info.httpDetails = httpResult.details;
        }
    } else {
        info.httpError = httpResult.error || 'ERR_FAILED';
        info.httpDetails = httpResult.details || 'Connection failed';
    }

    // Check HTTPS port (443)
    const httpsResult = await (async () => {
        const startTime = Date.now();
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            let corsError = null;
            let gotOpaqueResponse = false;
            
            // Try CORS mode first
            const httpsResponse = await fetch(`https://${ip}/`, {
                method: 'HEAD',
                mode: 'cors',
                cache: 'no-cache',
                signal: controller.signal
            }).catch(async (err) => {
                corsError = err;
                // Try no-cors mode
                try {
                    const noCorsResponse = await fetch(`https://${ip}/`, {
                        method: 'GET',
                        mode: 'no-cors',
                        cache: 'no-cache',
                        signal: controller.signal
                    });
                    if (noCorsResponse && noCorsResponse.type === 'opaque') {
                        gotOpaqueResponse = true;
                    }
                    return noCorsResponse;
                } catch (fallbackErr) {
                    throw corsError; // Use original error
                }
            });
            
            clearTimeout(timeoutId);
            const responseTime = Date.now() - startTime;
            
            if (httpsResponse) {
                if (httpsResponse.type === 'opaque' || gotOpaqueResponse) {
                    // Server responded but CORS blocked - could be 200, 302, etc.
                    return {
                        accessible: true,
                        status: 'CORS Blocked',
                        // error: 'CORS_BLOCKED',
                        details: 'Server responded (status could be 200/302/etc), CORS blocks details'
                    };
                } else {
                    // Full response received
                    return {
                        accessible: true,
                        status: httpsResponse.status,
                        statusText: httpsResponse.statusText
                    };
                }
            }
        } catch (e) {
            const responseTime = Date.now() - startTime;
            const analysis = analyzeError(e, 'https', ip, null, false, responseTime);
            return {
                accessible: false,
                error: analysis.errorType,
                details: analysis.details
            };
        }
    })();

    console.log(`${ip} HTTPS check result:`, httpsResult);
    if (httpsResult.accessible) {
        info.ports.https = true;
        info.httpsStatus = httpsResult.status;
        if (httpsResult.error) {
            info.httpsError = httpsResult.error;
            info.httpsDetails = httpsResult.details;
        }
    } else {
        info.httpsError = httpsResult.error || 'ERR_FAILED';
        info.httpsDetails = httpsResult.details || 'Connection failed';
    }

    console.log(`getHostInfo result for ${ip}:`, info);
    return info;
}

// Perform network scan
async function performScan() {
    const networkBase = document.getElementById('networkBase').value.trim();
    const startRange = parseInt(document.getElementById('startRange').value);
    const endRange = parseInt(document.getElementById('endRange').value);
    const timeout = parseInt(document.getElementById('timeout').value);

    if (!networkBase || !networkBase.match(/^(\d{1,3}\.){2}\d{1,3}$/)) {
        alert('Please enter a valid network base (e.g., 192.168.1)');
        return;
    }

    if (startRange < 1 || endRange > 254 || startRange > endRange) {
        alert('Please enter a valid IP range (1-254)');
        return;
    }

    updateTimeEstimate();

    // Reset scan count but preserve hosts if they exist
    scanActive = true;
    scannedCount = 0;
    
    const resultsDiv = document.getElementById('results');
    const progressContainer = document.getElementById('progressContainer');
    const scanBtn = document.getElementById('scanBtn');
    const stopBtn = document.getElementById('stopBtn');
    const exportBtn = document.getElementById('exportBtn');
    const clearBtn = document.getElementById('clearBtn');

    scanBtn.disabled = true;
    stopBtn.disabled = false;
    clearBtn.disabled = true;
    progressContainer.style.display = 'block';
    
    if (hostsMap.size === 0) {
        resultsDiv.innerHTML = '<p class="loading">Scanning network...</p>';
    }

    const totalIPs = endRange - startRange + 1;
    const batchSize = SCAN_BATCH_SIZE; // Reduced batch size for more reliable scanning

    for (let i = startRange; i <= endRange && scanActive; i += batchSize) {
        const batch = [];
        const batchEnd = Math.min(i + batchSize - 1, endRange);

        for (let j = i; j <= batchEnd; j++) {
            const ip = `${networkBase}.${j}`;
            batch.push(scanIP(ip, timeout));
        }

        const results = await Promise.all(batch);
        
        // Process results and get additional info for active hosts
        for (const result of results) {
            scannedCount++;
            if (result.active) {
                const now = new Date().toISOString();
                
                // Check if host already exists
                if (hostsMap.has(result.ip)) {
                    // Update existing host
                    const existingHost = hostsMap.get(result.ip);
                    existingHost.lastSeen = now;
                    existingHost.responseTime = result.responseTime;
                } else {
                    // Get additional host information for new hosts
                    const hostInfo = await getHostInfo(result.ip);
                    hostsMap.set(result.ip, {
                        ...result,
                        ...hostInfo,
                        firstSeen: now,
                        lastSeen: now
                    });
                }
                updateResults(); // Update after each active host is found
            }
        }

        updateProgress(scannedCount, totalIPs);
    }

    // Scan complete
    scanActive = false;
    scanBtn.disabled = false;
    stopBtn.disabled = true;
    clearBtn.disabled = false;
    if (hostsMap.size > 0) {
        exportBtn.style.display = 'inline-block';
    }
    
    if (hostsMap.size === 0) {
        resultsDiv.innerHTML = '<p class="info">No active hosts found. Note: This scan method has limitations due to browser security. Not all devices may be detected.</p>';
    }
    
    // Check if auto-repeat is enabled
    const autoRepeat = document.getElementById('autoRepeat').checked;
    if (autoRepeat && !autoRepeatInterval) {
        const repeatDelay = 10000; // 10 seconds between scans
        autoRepeatInterval = setTimeout(() => {
            autoRepeatInterval = null;
            performScan();
        }, repeatDelay);
    }
}

function updateProgress(current, total) {
    const percentage = (current / total) * 100;
    document.getElementById('progressFill').style.width = percentage + '%';
    document.getElementById('progressText').textContent = `Scanning: ${current}/${total} (${Math.round(percentage)}%)`;
}

function formatDuration(totalMs) {
    if (!Number.isFinite(totalMs) || totalMs <= 0) {
        return '0s';
    }

    if (totalMs < 1000) {
        return `${Math.ceil(totalMs)}ms`;
    }

    const totalSeconds = Math.ceil(totalMs / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    const parts = [];
    if (hours > 0) {
        parts.push(`${hours}h`);
    }
    if (minutes > 0) {
        parts.push(`${minutes}m`);
    }
    if (seconds > 0 || parts.length === 0) {
        parts.push(`${seconds}s`);
    }

    return parts.join(' ');
}

function renderRangeTimeEstimates(activeBase) {
    const container = document.getElementById('rangeTimeEstimate');
    if (!container) {
        return;
    }

    const lines = RANGE_SCAN_ORDER.map(rangeKey => {
        const config = RANGE_SCAN_CONFIG[rangeKey];
        if (!config) {
            return '';
        }

        const ipCount = config.end - config.start + 1;
        const batchCount = Math.ceil(ipCount / RANGE_SCAN_BATCH_SIZE);
        const totalMs = batchCount * RANGE_SCAN_TIMEOUT;
        const approxSeconds = Math.ceil(totalMs / 1000);
        const humanReadable = formatDuration(totalMs);
        const activeClass = rangeKey === activeBase ? ' estimate-line-active' : '';

        return `<div class="estimate-line${activeClass}">${config.label}: ~${approxSeconds}s (${humanReadable}), ~${RANGE_SCAN_TIMEOUT}ms/IP x ${ipCount} IPs</div>`;
    }).filter(Boolean).join('');

    if (lines) {
        container.innerHTML = `<div class="estimate-heading">Estimated duration per range</div>${lines}`;
    } else {
        container.innerHTML = '';
    }
}

function updateTimeEstimate() {
    const estimateEl = document.getElementById('timeEstimate');
    if (!estimateEl) {
        return;
    }

    const start = parseInt(document.getElementById('startRange').value, 10);
    const end = parseInt(document.getElementById('endRange').value, 10);
    const timeout = parseInt(document.getElementById('timeout').value, 10);

    if (Number.isNaN(start) || Number.isNaN(end) || Number.isNaN(timeout) || timeout <= 0 || start > end) {
        estimateEl.textContent = 'Estimated duration: —';
        return;
    }

    const ipCount = end - start + 1;
    if (ipCount <= 0) {
        estimateEl.textContent = 'Estimated duration: 0s';
        return;
    }

    const batchCount = Math.ceil(ipCount / SCAN_BATCH_SIZE);
    const totalMs = batchCount * timeout;
    const ipLabel = ipCount === 1 ? 'IP' : 'IPs';
    estimateEl.textContent = `Estimated duration: ${formatDuration(totalMs)} (~${timeout}ms/IP x ${ipCount} ${ipLabel})`;
}

// Helper function to get CSS class for error type
function getErrorClass(error) {
    if (!error) return 'error-unknown';
    
    const errorStr = String(error).toUpperCase();
    
    if (errorStr.includes('MIXED_CONTENT')) {
        return 'error-mixed-content';
    }
    if (errorStr.includes('TIMED_OUT') || errorStr.includes('TIMEOUT')) {
        return 'error-timeout';
    }
    if (errorStr.includes('REFUSED')) {
        return 'error-refused';
    }
    if (errorStr.includes('CORS')) {
        return 'error-cors';
    }
    if (errorStr.includes('CERT') || errorStr.includes('SSL')) {
        return 'error-cert';
    }
    if (errorStr.includes('ERR_FAILED') || errorStr.includes('TYPEERROR')) {
        return 'error-failed';
    }
    
    return 'error-other';
}

function updateResults() {
    const activeHosts = Array.from(hostsMap.values());
    
    // Sort by IP address numerically
    activeHosts.sort((a, b) => {
        const partsA = a.ip.split('.').map(Number);
        const partsB = b.ip.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            if (partsA[i] !== partsB[i]) {
                return partsA[i] - partsB[i];
            }
        }
        return 0;
    });
    
    document.getElementById('activeCount').textContent = activeHosts.length;
    document.getElementById('scannedCount').textContent = scannedCount;

    const resultsDiv = document.getElementById('results');

    if (activeHosts.length > 0) {
        const rowsHTML = activeHosts.map(host => {
            const firstSeen = host.firstSeen ? new Date(host.firstSeen).toLocaleString() : 'N/A';
            const lastSeen = host.lastSeen ? new Date(host.lastSeen).toLocaleString() : 'N/A';

            // Build response codes column with detailed error information
            const responseCodes = [];
            
            if (host.ports?.http) {
                const httpCode = typeof host.httpStatus === 'number' 
                    ? host.httpStatus 
                    : (host.httpStatus || 'N/A');
                const errorClass = host.httpError ? getErrorClass(host.httpError) : 'status-ok';
                const errorInfo = host.httpError ? `<br><span class="${errorClass}">${host.httpError}</span>` : '';
                const details = host.httpDetails ? `<br><span class="error-details">${host.httpDetails}</span>` : '';
                responseCodes.push(`<div class="status-line">HTTP: <span class="status-ok">${httpCode}</span>${errorInfo}${details}</div>`);
            } else if (host.httpError) {
                const errorClass = getErrorClass(host.httpError);
                const details = host.httpDetails ? `<br><span class="error-details">${host.httpDetails}</span>` : '';
                responseCodes.push(`<div class="status-line"><span class="${errorClass}">HTTP: ${host.httpError}</span>${details}</div>`);
            } else {
                responseCodes.push(`<div class="status-line muted">HTTP: Not checked</div>`);
            }
            
            if (host.ports?.https) {
                const httpsCode = typeof host.httpsStatus === 'number' 
                    ? host.httpsStatus 
                    : (host.httpsStatus || 'N/A');
                const errorClass = host.httpsError ? getErrorClass(host.httpsError) : 'status-ok';
                const errorInfo = host.httpsError ? `<br><span class="${errorClass}">${host.httpsError}</span>` : '';
                const details = host.httpsDetails ? `<br><span class="error-details">${host.httpsDetails}</span>` : '';
                responseCodes.push(`<div class="status-line">HTTPS: <span class="status-ok">${httpsCode}</span>${errorInfo}${details}</div>`);
            } else if (host.httpsError) {
                const errorClass = getErrorClass(host.httpsError);
                const details = host.httpsDetails ? `<br><span class="error-details">${host.httpsDetails}</span>` : '';
                responseCodes.push(`<div class="status-line"><span class="${errorClass}">HTTPS: ${host.httpsError}</span>${details}</div>`);
            } else {
                responseCodes.push(`<div class="status-line muted">HTTPS: Not checked</div>`);
            }
            
            const responseHTML = responseCodes.join('');

            return `
                <tr>
                    <td>
                        <div class="ip-cell">
                            <span class="ip-address">${host.ip}</span>
                            <span class="status-badge status-active">Active</span>
                            ${host.responseTime ? `<span class="response-time">${host.responseTime} ms</span>` : ''}
                        </div>
                    </td>
                    <td>
                        <div class="meta-info">First: ${firstSeen}</div>
                        <div class="meta-info">Last: ${lastSeen}</div>
                    </td>
                    <td class="response-codes-column" style="display: ${responseCodesVisible ? '' : 'none'};">${responseHTML}</td>
                    <td>
                        <div class="port-buttons compact">
                            <button class="port-btn ${host.ports?.http ? 'port-open' : 'port-unknown'}" 
                                    onclick="window.open('http://${host.ip}', '_blank')" 
                                    title="Open HTTP (port 80)">
                                <span class="port-icon">🌐</span> HTTP:80
                            </button>
                            <button class="port-btn ${host.ports?.https ? 'port-open' : 'port-unknown'}" 
                                    onclick="window.open('https://${host.ip}', '_blank')" 
                                    title="Open HTTPS (port 443)">
                                <span class="port-icon">🔒</span> HTTPS:443
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        const displayStyle = responseCodesVisible ? '' : 'none';
        const buttonOpacity = responseCodesVisible ? '1' : '0.5';
        const buttonTitle = responseCodesVisible ? 'Hide Response Codes' : 'Show Response Codes';
        
        resultsDiv.innerHTML = `
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Seen</th>
                        <th class="response-codes-column" style="display: ${displayStyle};">Response Codes</th>
                        <th>
                            <button class="toggle-codes-btn" onclick="toggleResponseCodes(this)" title="${buttonTitle}" style="opacity: ${buttonOpacity};">📊</button>
                            Actions
                        </th>
                    </tr>
                </thead>
                <tbody>${rowsHTML}</tbody>
            </table>
        `;
    } else {
        resultsDiv.innerHTML = '<p class="placeholder">No scan results yet. Start a scan to discover devices on your network.</p>';
    }
}

function stopScan() {
    scanActive = false;
    if (autoRepeatInterval) {
        clearTimeout(autoRepeatInterval);
        autoRepeatInterval = null;
    }
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('stopBtn').disabled = true;
    document.getElementById('clearBtn').disabled = false;
}

function clearResults() {
    hostsMap.clear();
    scannedCount = 0;
    
    document.getElementById('activeCount').textContent = '0';
    document.getElementById('scannedCount').textContent = '0';
    document.getElementById('results').innerHTML = '<p class="placeholder">No scan results yet. Start a scan to discover devices on your network.</p>';
    document.getElementById('exportBtn').style.display = 'none';
    document.getElementById('clearBtn').disabled = true;
    updateTimeEstimate();
}

function toggleAutoRepeat() {
    const autoRepeat = document.getElementById('autoRepeat').checked;
    
    if (!autoRepeat && autoRepeatInterval) {
        clearTimeout(autoRepeatInterval);
        autoRepeatInterval = null;
    }
}

function exportResults() {
    const activeHosts = Array.from(hostsMap.values());
    const data = {
        timestamp: new Date().toISOString(),
        totalScanned: scannedCount,
        activeHosts: activeHosts.map(h => ({
            ip: h.ip,
            hostname: h.hostname,
            responseTime: h.responseTime,
            ports: h.ports,
            firstSeen: h.firstSeen,
            lastSeen: h.lastSeen
        }))
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network-scan-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Show warning if running on HTTPS
    if (isHttpsPage) {
        const warningDiv = document.createElement('div');
        warningDiv.className = 'https-warning';
        warningDiv.innerHTML = `
            <strong>⚠️ Running on HTTPS:</strong> Browser security blocks HTTP (port 80) scanning from HTTPS pages. 
            Only HTTPS (port 443) will be scanned. For full scanning, visit <a href="http://lebon.info" target="_blank">http://lebon.info</a> 
            or run this scanner from a local file (file:///).
        `;
        const container = document.querySelector('.container');
        const header = container.querySelector('.header');
        container.insertBefore(warningDiv, header.nextSibling);
    }
    
    // Main scan controls
    document.getElementById('scanBtn').addEventListener('click', performScan);
    document.getElementById('stopBtn').addEventListener('click', stopScan);
    document.getElementById('clearBtn').addEventListener('click', clearResults);
    document.getElementById('autoRepeat').addEventListener('change', toggleAutoRepeat);
    document.getElementById('exportBtn').addEventListener('click', exportResults);

    // Time estimate updates
    ['startRange', 'endRange', 'timeout'].forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('input', updateTimeEstimate);
            input.addEventListener('change', updateTimeEstimate);
        }
    });
    
    // Info modal
    const infoBtn = document.getElementById('infoBtn');
    const infoModal = document.getElementById('infoModal');
    const closeBtn = infoModal.querySelector('.close');
    
    infoBtn.addEventListener('click', () => {
        infoModal.style.display = 'block';
    });
    
    closeBtn.addEventListener('click', () => {
        infoModal.style.display = 'none';
    });
    
    window.addEventListener('click', (event) => {
        if (event.target === infoModal) {
            infoModal.style.display = 'none';
        }
    });

    renderRangeTimeEstimates();
    updateTimeEstimate();
});

// Toggle response codes visibility
function toggleResponseCodes(button) {
    responseCodesVisible = !responseCodesVisible;
    
    const columns = document.querySelectorAll('.response-codes-column');
    columns.forEach(col => {
        col.style.display = responseCodesVisible ? '' : 'none';
    });
    
    // Update button appearance
    button.style.opacity = responseCodesVisible ? '1' : '0.5';
    button.title = responseCodesVisible ? 'Hide Response Codes' : 'Show Response Codes';
}
