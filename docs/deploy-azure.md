# Deploying to Azure Container Apps

This guide deploys patch-tuesday-mcp as an always-warm remote MCP server on
Azure Container Apps (ACA), with rate limiting, cost protections, and optional
Application Insights usage telemetry.

**Expected cost:** roughly **$5/month** at 0.25 vCPU / 0.5 GiB with one
always-on replica (after ACA's monthly free grants). Telemetry is free at this
scale (first 5 GB/month of App Insights ingestion included).

## 1. Build and push the image (Docker Hub — free for public images)

Using a free public registry avoids paying ~$5/month for Azure Container
Registry Basic. The live deployment uses Docker Hub:

```bash
docker build -t docker.io/xxbutler21xx/patch-tuesday-mcp:latest .
docker login docker.io -u xxbutler21xx
docker push docker.io/xxbutler21xx/patch-tuesday-mcp:latest
```

Make sure the repository is public on Docker Hub so ACA can pull it without
credentials. (GitHub Container Registry `ghcr.io` works the same way.)

## 2. Create the Container Apps environment

```bash
az group create --name patch-tuesday-rg --location eastus

az containerapp env create \
  --name patch-tuesday-env \
  --resource-group patch-tuesday-rg \
  --location eastus
```

## 3. (Optional) Create Application Insights for usage telemetry

```bash
az monitor app-insights component create \
  --app patch-tuesday-insights \
  --resource-group patch-tuesday-rg \
  --location eastus

# Capture the connection string for step 4
az monitor app-insights component show \
  --app patch-tuesday-insights \
  --resource-group patch-tuesday-rg \
  --query connectionString -o tsv
```

## 4. Deploy the container app

Always-warm (no cold starts), capped at 2 replicas so abuse cannot run up the
bill — worst case cost is bounded by the replica cap.

```bash
az containerapp create \
  --name patch-tuesday-mcp \
  --resource-group patch-tuesday-rg \
  --environment patch-tuesday-env \
  --image docker.io/xxbutler21xx/patch-tuesday-mcp:latest \
  --target-port 8000 \
  --ingress external \
  --cpu 0.25 --memory 0.5Gi \
  --min-replicas 1 \
  --max-replicas 2 \
  --scale-rule-name http-concurrency \
  --scale-rule-type http \
  --scale-rule-http-concurrency 100 \
  --env-vars \
    MCP_TRANSPORT=http \
    RATE_LIMIT_RPM=60 \
    APPLICATIONINSIGHTS_CONNECTION_STRING="<connection string from step 3, or omit>"
```

The MCP endpoint will be:

```
https://<app-fqdn>/mcp
```

Get the FQDN:

```bash
az containerapp show \
  --name patch-tuesday-mcp \
  --resource-group patch-tuesday-rg \
  --query properties.configuration.ingress.fqdn -o tsv
```

Connect from Claude Code:

```bash
claude mcp add --transport http patch-tuesday https://<app-fqdn>/mcp
```

## 5. Abuse protections in place

| Layer | Protection |
|-------|-----------|
| `--max-replicas 2` | Hard cost ceiling — a flood of requests cannot scale your bill |
| `RATE_LIMIT_RPM=60` | Per-client-IP token bucket, returns 429 with Retry-After. The client IP comes from the rightmost `X-Forwarded-For` entry (the one ACA ingress appends), so it cannot be spoofed |
| `MCP_MAX_BODY_BYTES` | Request bodies over 256 KB are rejected with 413 |
| Bounded caches | Month-document caches are size-capped (6 full / 40 slim parses), so iterating historical months cannot exhaust the 0.5 GiB container |
| In-process caching | Even hammered, the server hits the MSRC API at most ~hourly per month document, single-flighted across concurrent requests |
| Read-only public data | Nothing sensitive to leak; worst case is compute cost, which is capped |

HTTP mode is stateless, so both replicas can serve any request without
session affinity. `GET /health` is exempt from rate limiting and suitable
for ACA HTTP probes or external uptime checks.

## 6. Budget alert (recommended)

Get emailed as monthly spend approaches $30. `az consumption budget create`
cannot attach email notifications, so use the ARM API via `az rest` (this is
how the live budget is configured — email at 80% and 100% of $30):

```bash
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/<sub-id>/resourceGroups/patch-tuesday-rg/providers/Microsoft.Consumption/budgets/patch-tuesday-budget?api-version=2023-05-01" \
  --body '{
    "properties": {
      "category": "Cost",
      "amount": 30,
      "timeGrain": "Monthly",
      "timePeriod": {"startDate": "2026-07-01T00:00:00Z", "endDate": "2028-07-01T00:00:00Z"},
      "notifications": {
        "actual80": {"enabled": true, "operator": "GreaterThan", "threshold": 80,
                      "thresholdType": "Actual", "contactEmails": ["you@example.com"]},
        "actual100": {"enabled": true, "operator": "GreaterThan", "threshold": 100,
                       "thresholdType": "Actual", "contactEmails": ["you@example.com"]}
      }
    }
  }'
```

(Or set it up in Portal → Cost Management → Budgets, which also supports
action groups for email notifications.)

## 7. Useful App Insights KQL queries

Daily unique users (hashed IPs — raw addresses are never stored):

```kusto
traces
| where customDimensions.event_name == "http_request"
| extend user = tostring(customDimensions.custom_user_hash)
| summarize uniques = dcount(user) by bin(timestamp, 1d)
| order by timestamp desc
```

Requests per day:

```kusto
traces
| where customDimensions.event_name == "http_request"
| summarize requests = count() by bin(timestamp, 1d)
| order by timestamp desc
```

Which tool parameters people actually use:

```kusto
traces
| where customDimensions.event_name == "tool_call"
| extend params = tostring(customDimensions.custom_params_used)
| summarize calls = count() by params
| order by calls desc
```

Tool latency:

```kusto
traces
| where customDimensions.event_name == "tool_call"
| extend ms = todouble(customDimensions.custom_duration_ms)
| summarize p50 = percentile(ms, 50), p95 = percentile(ms, 95) by bin(timestamp, 1d)
```

Error rate by kind (invalid_input / not_found / upstream — a spike in
`upstream` means the MSRC API is having a bad day):

```kusto
traces
| where customDimensions.event_name == "tool_call"
| extend kind = tostring(customDimensions.custom_error_kind)
| summarize calls = count() by kind, bin(timestamp, 1d)
| order by timestamp desc
```

Upstream MSRC fetch latency and cache effectiveness (`msrc_fetch` events are
emitted only on cache misses, so misses/tool-calls approximates the miss
rate):

```kusto
traces
| where customDimensions.event_name == "msrc_fetch"
| extend ms = todouble(customDimensions.custom_duration_ms)
| summarize fetches = count(), p95_ms = percentile(ms, 95) by bin(timestamp, 1d)
```

**Ingestion cost:** the first 5 GB/month are free, which is plenty at this
scale. If usage grows, `configure_azure_monitor` supports `sampling_ratio`
(and recent versions default to rate-limited trace sampling); log-based
events like `tool_call` can be trimmed by raising the exported log level.

## 8. Updating the deployment

```bash
docker build -t docker.io/xxbutler21xx/patch-tuesday-mcp:latest .
docker push docker.io/xxbutler21xx/patch-tuesday-mcp:latest

az containerapp update \
  --name patch-tuesday-mcp \
  --resource-group patch-tuesday-rg \
  --image docker.io/xxbutler21xx/patch-tuesday-mcp:latest
```

Tip: push a version tag (e.g. `:0.3.0`) alongside `:latest` and deploy the
tag — `az containerapp update` with an unchanged image reference will not
roll a new revision.
