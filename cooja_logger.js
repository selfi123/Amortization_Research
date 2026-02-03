/* Cooja Script: Run Protocol & Save Logs to File */

// 1. Setup the File Writer
var FileWriter = java.io.FileWriter;
var out = new FileWriter("simulation_results.log");

TIMEOUT(1200000); // 20 minutes timeout

// Write a header to the file
out.write("Timestamp\tNodeID\tMessage\n");
out.write("--------------------------------------------------\n");

var metrics = {};

function addMetric(key, value) {
    if (!metrics[key]) {
        metrics[key] = [];
    }
    metrics[key].push(value);
}

function writeSummary() {
    out.write("\n\n==================================================\n");
    out.write("             SIMULATION METRICS SUMMARY           \n");
    out.write("==================================================\n");

    // A. Cryptographic Computation Cost
    out.write("\n[A] CRYPTOGRAPHIC COMPUTATION COST (Ticks)\n");
    var cryptoKeys = ["COST_AUTH_KEYGEN", "COST_AUTH_SIGN_ATTEMPT_0", "COST_AUTH_VERIFY", "COST_DATA_ENCRYPT", "COST_DATA_DECRYPT"];
    for (var i = 0; i < cryptoKeys.length; i++) {
        var k = cryptoKeys[i];
        if (metrics[k]) out.write("  - " + k + ": " + metrics[k].join(", ") + "\n");
    }

    // B. Energy Per Phase
    out.write("\n[B] ENERGY CONSUMPTION (Ticks Diff)\n");
    var phases = ["AUTH", "DATA"];
    var types = ["CPU", "LPM", "TX", "RX"];
    for (var p = 0; p < phases.length; p++) {
        out.write("  Phase: " + phases[p] + "\n");
        for (var t = 0; t < types.length; t++) {
            var k = "ENERGY_" + phases[p] + "_" + types[t];
            if (metrics[k]) out.write("    - " + k + ": " + metrics[k].join(", ") + "\n");
        }
    }

    // C. Communication Overhead
    out.write("\n[C] COMMUNICATION OVERHEAD (Bytes)\n");
    var commKeys = ["COMM_AUTH_PACKET_SIZE", "COMM_PROXY_AUTH_SIZE", "COMM_DATA_PACKET_SIZE", "COMM_PROXY_DATA_SIZE"];
    for (var i = 0; i < commKeys.length; i++) {
        var k = commKeys[i];
        if (metrics[k]) out.write("  - " + k + ": " + metrics[k].join(", ") + "\n");
    }

    // D. Session Level Metrics
    out.write("\n[D] SESSION METRICS\n");
    var sessionKeys = ["SESSIONS_PER_AUTH", "SESSION_MESSAGE_COUNT", "SESSION_LIFETIME"];
    for (var i = 0; i < sessionKeys.length; i++) {
        var k = sessionKeys[i];
        if (metrics[k]) out.write("  - " + k + ": " + metrics[k].join(", ") + "\n");
    }

    // E. Latency Metrics
    out.write("\n[E] LATENCY METRICS (Ticks)\n");
    var latencyKeys = ["LATENCY_AUTH", "LATENCY_DATA_SEND", "LATENCY_E2E"];
    for (var i = 0; i < latencyKeys.length; i++) {
        var k = latencyKeys[i];
        if (metrics[k]) out.write("  - " + k + ": " + metrics[k].join(", ") + "\n");
    }

    out.write("==================================================\n");
}

while (true) {
    // 2. Capture the current line
    var logString = time + "\tID:" + id + "\t" + msg + "\n";

    // 3. Write to the file immediately
    try {
        out.write(logString);
        out.flush();
    } catch (e) {
        log.log("Error writing to file: " + e + "\n");
    }

    // 4. Also print to Cooja GUI
    log.log(time + ":" + id + ":" + msg + "\n");

    // Parse Metrics
    if (msg.startsWith("[METRIC]")) {
        // Format: [METRIC] KEY: VALUE
        var parts = msg.split(":");
        if (parts.length >= 2) {
            var keyStr = parts[0].replace("[METRIC] ", "").trim();
            var valStr = parts[1].trim();
            addMetric(keyStr, valStr);
        }
    }

    // 5. Check for Success/Failure Logic
    if (msg.contains("Ring-LWE key generation successful")) {
        log.log("STEP 1: Key Generation Complete for Node " + id + "\n");
        out.write("# STEP 1 COMPLETED\n");
    }

    if (msg.contains("PACKET_RECEIVED_SUCCESS")) {
        log.log("STEP 2: Authentication Packet Received by Gateway\n");
        out.write("# STEP 2 COMPLETED\n");
    }

    if (msg.contains("Protocol Complete")) {
        // Wait a bit to ensure all metrics flush then close
        log.log("Sender finished. Waiting for final flush...\n");
    }

    if (msg.contains("Protocol execution successful")) {
        log.log("STEP 3: Full Protocol Cycle Complete! TEST OK\n");
        out.write("# TEST SUCCESS: PROTOCOL COMPLETE\n");

        writeSummary(); /* <--- Write the summary at the end */

        out.close();
        log.testOK();
    }

    if (msg.contains("Authentication timeout")) {
        log.log("TEST FAILED: Authentication Timeout\n");
        out.write("# TEST FAILED: TIMEOUT\n");
        out.close();
        log.testFailed();
    }

    // Wait for the next message
    YIELD();
}
