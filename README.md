# sldtracker

`sldtracker` is a high-performance system for real-time tracking and analysis of second-level domains (SLDs) from live network traffic. It captures domains from DNS queries, as well as from TLS and QUIC Client Hello SNI extensions, and provides fast APIs to inspect trending domains.

## Features

-  **SLD Extraction:** Parses DNS queries and TLS/QUIC SNI to extract second-level domains (e.g., `google.com` from `mail.google.com`)
-  **High-performance packet sniffer:** Uses `gopacket` to capture traffic directly from a network interface (e.g., `en0`)
-  **In-memory aggregation:** Maintains an in-memory time-windowed count of seen SLDs with minimal latency
-  **Trending domains API:** Exposes an API to query top-N SLDs in the last M minutes
-  **Pluggable extractors:** Cleanly separates DNS, TLS, and QUIC domain extraction logic for easy extensibility

## Use Case

You can use `sldtracker` to:

- Monitor domain usage on a network
- Detect sudden spikes in unknown or suspicious domains
- Power real-time dashboards of active domains
- Feed security or policy engines with live SLD data

## How It Works

1. **Packet Capture:**
   - Listens on a specified network interface
   - Captures DNS packets, TLS Client Hello, and QUIC Client Hello

2. **Domain Extraction:**
   - Extracts FQDNs from packets
   - Normalizes and parses to obtain SLD (second-level domain)

3. **SLD Aggregation:**
   - Maintains a time-windowed count of SLDs (e.g., last 5 minutes)
   - Efficient data structure for fast lookup and top-N queries

4. **API (optional):**
   - HTTP API to fetch trending SLDs
   - Query interface for recent activity

## Example

```sh
go build
sudo ./sldtracker

Live -  en0
2025/04/14 18:05:46 Server started on :8081
2025/04/14 18:05:50 Got dns.google
2025/04/14 18:05:50 Got dns.google
