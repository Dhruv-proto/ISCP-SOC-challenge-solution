# Deployment Strategy — Project Guardian 2.0

### Objective  
We need a reliable way to stop PII from leaking through logs, APIs, and unmonitored endpoints. The solution should be fast enough to sit in the data path, easy to roll out across services, and flexible enough to cover legacy systems.

---

## Where to Place the Detector
After weighing latency, scale, and cost, the detector should live in three main spots:

1. **API Gateway Plugin**  
   - First line of defense.  
   - Sanitizes request/response payloads before they reach backend services.  
   - Ideal because every external call already passes through the gateway.

2. **Sidecar Container (per service)**  
   - Protects internal logs and service-to-service calls.  
   - Each application pod gets a lightweight redactor sidecar that masks PII before logs leave the pod.  
   - This limits blast radius if a single service misbehaves.

3. **DaemonSet (per node)**  
   - Useful for legacy or non-containerized apps.  
   - Runs on every node, monitors mirrored traffic, and performs redaction or alerts when PII slips through.  
   - Offloads heavy scanning tasks away from the critical request path.

---

## How It Fits Together
- Client request → hits **API Gateway plugin** → payload is checked and redacted.  
- Backend service runs with a **sidecar** → protects logs and internal telemetry.  
- **DaemonSet** watches node traffic for anything missed.  
- All redaction events are pushed asynchronously to an **audit pipeline** (e.g., Kafka) with only metadata, never raw PII.  

---

## Why This Layout
- **Latency:** Gateway + sidecar redaction is fast (regex, deterministic rules).  
- **Coverage:** Sidecars catch log leaks, gateway covers external traffic, DaemonSet covers the rest.  
- **Scalability:** Stateless detectors, scale horizontally.  
- **Cost:** Heavy analysis can be moved to the async audit pipeline, so production traffic only uses lightweight checks.

---

## Rollout Plan
1. Start with one service behind the gateway, run the plugin + PII service in staging.  
2. Deploy a sidecar to a single namespace to measure overhead and false positives.  
3. Add DaemonSet monitoring for older systems.  
4. Roll out cluster-wide once performance is validated.  
5. Tune regex/whitelists and introduce ML-based scans in the audit pipeline for long-term improvements.

---

## Monitoring
Track:  
- How many redactions happen per service.  
- Extra latency added per request.  
- False positive rate (sampled).  
- Component uptime (gateway plugin, sidecars, DaemonSet).  

Set alerts if redactions spike suddenly (could mean a new leak or bug).

---

### Summary
This layered setup gives strong protection without hurting performance: fast regex checks inline, detailed analysis offline. It scales with the cluster, can be rolled out gradually, and provides an audit trail for compliance.
