import requests
import time
import json
import statistics
import random
from datetime import datetime
from collections import Counter

BASE_URL = "https://thekavach.onrender.com"

def test_health():
    print("[1/7] Testing /api/health...")
    r = requests.get(f"{BASE_URL}/api/health")
    assert r.status_code == 200, f"Health check failed: {r.status_code}"
    data = r.json()
    print(f"  Status: {data['status']}, Rows: {data['dataset_rows']}")
    return data

def test_generate_key():
    print("[2/7] Testing /api/generate-key...")
    r = requests.post(f"{BASE_URL}/api/generate-key", json={"name": "TestUser"})
    assert r.status_code == 200, f"Key generation failed: {r.status_code}"
    key = r.json()["api_key"]
    print(f"  Key: {key[:20]}...")
    return key

def test_logs(key, count=100):
    print(f"[3/7] Testing /api/logs (count={count})...")
    start = time.time()
    r = requests.get(f"{BASE_URL}/api/logs", params={"count": count},
                     headers={"Authorization": f"Bearer {key}"})
    elapsed = time.time() - start
    assert r.status_code == 200, f"Logs failed: {r.status_code}"
    data = r.json()
    print(f"  Got {data['count']} logs in {elapsed*1000:.0f}ms")
    return data, elapsed

def test_stream(key, duration=10):
    print(f"[4/7] Testing /api/stream ({duration}s)...")
    start = time.time()
    r = requests.get(f"{BASE_URL}/api/stream?interval=0.2",
                     headers={"Authorization": f"Bearer {key}"}, stream=True, timeout=duration+5)
    logs = []
    for line in r.iter_lines():
        if line and line.decode().startswith("data: "):
            logs.append(json.loads(line.decode()[6:]))
        if time.time() - start > duration:
            break
    print(f"  Received {len(logs)} logs in {duration}s ({len(logs)/duration:.1f} logs/sec)")
    return logs

def test_status():
    print("[5/7] Testing /api/status...")
    r = requests.get(f"{BASE_URL}/api/status")
    assert r.status_code == 200
    data = r.json()
    print(f"  Uptime: {data['uptime']['formatted']}, Version: {data['version']}")
    return data

def test_stats(key):
    print("[6/7] Testing /api/stats...")
    r = requests.get(f"{BASE_URL}/api/stats",
                     headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    data = r.json()
    print(f"  Threat distribution: {data.get('threat_distribution', {}).get('top_values', {})}")
    return data

def test_ai_status():
    print("[7/7] Testing /api/ai/status...")
    r = requests.get(f"{BASE_URL}/api/ai/status")
    assert r.status_code == 200
    data = r.json()
    print(f"  AI available: {data['available']}")
    return data

def analyze_randomness(logs):
    print("\n=== RANDOMNESS ANALYSIS ===")
    if not logs:
        return {}
    
    src_ips = [l["source_ip"] for l in logs]
    dest_ips = [l["dest_ip"] for l in logs]
    protocols = [l["protocol"] for l in logs]
    threats = [l["threat_label"] for l in logs]
    actions = [l["action"] for l in logs]
    bytes_list = [l["bytes_transferred"] for l in logs]
    
    metrics = {
        "unique_source_ips": len(set(src_ips)),
        "unique_dest_ips": len(set(dest_ips)),
        "unique_protocols": len(set(protocols)),
        "protocol_distribution": dict(Counter(protocols)),
        "threat_distribution": dict(Counter(threats)),
        "action_distribution": dict(Counter(actions)),
        "bytes_mean": round(statistics.mean(bytes_list), 1),
        "bytes_std": round(statistics.stdev(bytes_list), 1) if len(bytes_list) > 1 else 0,
        "bytes_min": min(bytes_list),
        "bytes_max": max(bytes_list),
        "ip_entropy_src": round(-sum((c/len(src_ips)) * __import__("math").log2(c/len(src_ips)) for c in Counter(src_ips).values()), 2),
        "ip_entropy_dest": round(-sum((c/len(dest_ips)) * __import__("math").log2(c/len(dest_ips)) for c in Counter(dest_ips).values()), 2),
    }
    
    for k, v in metrics.items():
        if k not in ["protocol_distribution", "threat_distribution", "action_distribution"]:
            print(f"  {k}: {v}")
    print(f"  Protocols: {metrics['protocol_distribution']}")
    print(f"  Threats: {metrics['threat_distribution']}")
    return metrics

def analyze_speed(log_results, stream_logs, stream_duration):
    print("\n=== SPEED ANALYSIS ===")
    if not log_results:
        return {}
    
    batch_times = [r[1] for r in log_results]
    metrics = {
        "batch_request_count": len(log_results),
        "batch_mean_ms": round(statistics.mean(batch_times) * 1000, 1),
        "batch_median_ms": round(statistics.median(batch_times) * 1000, 1),
        "batch_min_ms": round(min(batch_times) * 1000, 1),
        "batch_max_ms": round(max(batch_times) * 1000, 1),
        "batch_p95_ms": round(sorted(batch_times)[int(len(batch_times)*0.95)] * 1000, 1),
        "stream_logs_received": len(stream_logs),
        "stream_duration_sec": stream_duration,
        "stream_rate_logs_per_sec": round(len(stream_logs) / stream_duration, 1),
    }
    
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    return metrics

def generate_graphs(metrics, output_dir="docs"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    
    # Speed chart
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("TheKavach - Performance & Quality Metrics", fontsize=14, fontweight="bold")
    
    # 1. Response time distribution
    batch_times = metrics.get("batch_times_ms", [50])
    axes[0, 0].hist(batch_times, bins=20, color="#22c55e", edgecolor="white", alpha=0.8)
    axes[0, 0].set_title("Response Time Distribution (ms)")
    axes[0, 0].set_xlabel("Response Time (ms)")
    axes[0, 0].set_ylabel("Count")
    axes[0, 0].axvline(metrics.get("batch_mean_ms", 50), color="red", linestyle="--", label="Mean")
    axes[0, 0].legend()
    
    # 2. Threat distribution
    threat_dist = metrics.get("threat_distribution", {})
    if threat_dist:
        labels = list(threat_dist.keys())
        values = list(threat_dist.values())
        colors = ["#22c55e" if l == "benign" else "#eab308" if l == "suspicious" else "#ef4444" for l in labels]
        axes[0, 1].bar(labels, values, color=colors, edgecolor="white")
        axes[0, 1].set_title("Threat Label Distribution")
        axes[0, 1].set_ylabel("Count")
    
    # 3. Protocol distribution
    proto_dist = metrics.get("protocol_distribution", {})
    if proto_dist:
        labels = list(proto_dist.keys())
        values = list(proto_dist.values())
        axes[1, 0].barh(labels[::-1], values[::-1], color="#3b82f6", edgecolor="white")
        axes[1, 0].set_title("Protocol Distribution")
        axes[1, 0].set_xlabel("Count")
    
    # 4. Bytes transferred distribution
    bytes_data = metrics.get("bytes_samples", [])
    if bytes_data:
        axes[1, 1].hist(bytes_data, bins=30, color="#8b5cf6", edgecolor="white", alpha=0.8)
        axes[1, 1].set_title("Bytes Transferred Distribution")
        axes[1, 1].set_xlabel("Bytes")
        axes[1, 1].set_ylabel("Count")
    
    plt.tight_layout()
    plt.savefig(f"{output_dir}/metrics_chart.png", dpi=150, bbox_inches="tight", facecolor="#09090b")
    plt.close()
    print(f"\nChart saved to {output_dir}/metrics_chart.png")

def main():
    print("=" * 60)
    print("TheKavach - Synthetic Data Quality & Performance Test")
    print(f"Target: {BASE_URL}")
    print(f"Time: {datetime.now().isoformat()}")
    print("=" * 60)
    
    results = {"test_time": datetime.now().isoformat(), "base_url": BASE_URL}
    
    # Run tests
    health = test_health()
    results["health"] = health
    
    key = test_generate_key()
    results["api_key"] = key[:20] + "..."
    
    # Batch log tests (20 requests)
    log_results = []
    all_logs = []
    print("\n[Running 20 batch log requests...]")
    for i in range(20):
        data, elapsed = test_logs(key, count=50)
        log_results.append((data, elapsed))
        all_logs.extend(data["logs"])
    
    results["total_logs_generated"] = len(all_logs)
    
    # Stream test
    stream_logs = test_stream(key, duration=15)
    all_logs.extend(stream_logs)
    
    status = test_status()
    results["status"] = status
    
    stats = test_stats(key)
    results["stats"] = stats
    
    ai_status = test_ai_status()
    results["ai_status"] = ai_status
    
    # Analyze
    randomness = analyze_randomness(all_logs)
    speed = analyze_speed(log_results, stream_logs, 15)
    
    # Collect raw data for graphs
    metrics_for_graph = {
        "batch_times_ms": [round(r[1]*1000, 1) for r in log_results],
        "batch_mean_ms": speed.get("batch_mean_ms", 0),
        "threat_distribution": randomness.get("threat_distribution", {}),
        "protocol_distribution": randomness.get("protocol_distribution", {}),
        "bytes_samples": [l["bytes_transferred"] for l in all_logs],
    }
    
    # Generate graphs
    try:
        generate_graphs(metrics_for_graph)
    except Exception as e:
        print(f"Graph generation skipped (matplotlib not available): {e}")
    
    # Compile final metrics
    results["randomness"] = randomness
    results["speed"] = speed
    results["total_unique_source_ips"] = randomness.get("unique_source_ips", 0)
    results["total_unique_dest_ips"] = randomness.get("unique_dest_ips", 0)
    results["threat_ratio"] = randomness.get("threat_distribution", {})
    results["bytes_stats"] = {
        "mean": randomness.get("bytes_mean", 0),
        "std": randomness.get("bytes_std", 0),
        "min": randomness.get("bytes_min", 0),
        "max": randomness.get("bytes_max", 0),
    }
    
    # Save metrics
    with open("docs/test_metrics.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nMetrics saved to docs/test_metrics.json")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total logs generated: {len(all_logs)}")
    print(f"Unique source IPs: {randomness.get('unique_source_ips', 0)}")
    print(f"Unique dest IPs: {randomness.get('unique_dest_ips', 0)}")
    print(f"Avg response time: {speed.get('batch_mean_ms', 0)}ms")
    print(f"Stream rate: {speed.get('stream_rate_logs_per_sec', 0)} logs/sec")
    print(f"Threat distribution: {randomness.get('threat_distribution', {})}")
    print("=" * 60)
    print("TEST COMPLETE")

if __name__ == "__main__":
    main()
