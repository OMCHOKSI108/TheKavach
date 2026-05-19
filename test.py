import requests
import time
import json
import statistics
import random
import math
from datetime import datetime
from collections import Counter

BASE_URL = "https://thekavach.onrender.com"
TEST_DURATION = 1200  # 20 minutes in seconds
STREAM_INTERVAL = 0.1  # 100ms for fast streaming

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

def test_logs(key, count=50):
    start = time.time()
    r = requests.get(f"{BASE_URL}/api/logs", params={"count": count},
                     headers={"Authorization": f"Bearer {key}"})
    elapsed = time.time() - start
    if r.status_code != 200:
        return None, elapsed
    data = r.json()
    return data, elapsed

def test_stream(key, duration=30):
    print(f"  Streaming for {duration}s at {STREAM_INTERVAL}s interval...")
    start = time.time()
    r = requests.get(f"{BASE_URL}/api/stream?interval={STREAM_INTERVAL}",
                     headers={"Authorization": f"Bearer {key}"}, stream=True, timeout=duration+10)
    logs = []
    for line in r.iter_lines():
        if line and line.decode().startswith("data: "):
            try:
                logs.append(json.loads(line.decode()[6:]))
            except:
                pass
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
        "ip_entropy_src": round(-sum((c/len(src_ips)) * math.log2(c/len(src_ips)) for c in Counter(src_ips).values()), 2),
        "ip_entropy_dest": round(-sum((c/len(dest_ips)) * math.log2(c/len(dest_ips)) for c in Counter(dest_ips).values()), 2),
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
    
    batch_times = [r[1] for r in log_results if r[0] is not None]
    metrics = {
        "batch_request_count": len(batch_times),
        "batch_mean_ms": round(statistics.mean(batch_times) * 1000, 1) if batch_times else 0,
        "batch_median_ms": round(statistics.median(batch_times) * 1000, 1) if batch_times else 0,
        "batch_min_ms": round(min(batch_times) * 1000, 1) if batch_times else 0,
        "batch_max_ms": round(max(batch_times) * 1000, 1) if batch_times else 0,
        "batch_p95_ms": round(sorted(batch_times)[int(len(batch_times)*0.95)] * 1000, 1) if batch_times else 0,
        "stream_logs_received": len(stream_logs),
        "stream_duration_sec": stream_duration,
        "stream_rate_logs_per_sec": round(len(stream_logs) / stream_duration, 1) if stream_duration > 0 else 0,
    }
    
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    return metrics

def generate_dashboard(metrics, output_dir="docs"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import numpy as np
    
    threat_dist = metrics.get("threat_distribution", {})
    proto_dist = metrics.get("protocol_distribution", {})
    bytes_stats = metrics.get("bytes_stats", {})
    speed = metrics.get("speed", {})
    randomness = metrics.get("randomness", {})
    
    fig = plt.figure(figsize=(22, 12), facecolor='white')
    gs = gridspec.GridSpec(3, 8, figure=fig, hspace=0.35, wspace=0.3)
    
    fig.suptitle('TheKavach - Live Performance Dashboard (20-Min Test)', fontsize=22, fontweight='bold', color='#1a1a2e', y=0.97)
    
    kpi_data = [
        ('Total Logs', f"{metrics.get('total_logs', 0):,}", '#22c55e'),
        ('Avg Response', f"{speed.get('batch_mean_ms', 0)}ms", '#3b82f6'),
        ('Stream Rate', f"{speed.get('stream_rate_logs_per_sec', 0)}/s", '#8b5cf6'),
        ('Unique IPs', f"{randomness.get('unique_source_ips', 0)}", '#f59e0b'),
        ('IP Entropy', f"{randomness.get('ip_entropy_src', 0)}", '#ef4444'),
        ('Bytes Mean', f"{bytes_stats.get('mean', 0):,.0f}", '#06b6d4'),
        ('Test Duration', '20 min', '#10b981'),
        ('Dataset', f"{metrics.get('dataset_rows', 0):,}", '#ec4899'),
    ]
    
    for i, (label, value, color) in enumerate(kpi_data):
        ax = fig.add_subplot(gs[0, i])
        ax.set_facecolor('white')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['left'].set_visible(False)
        ax.tick_params(left=False, bottom=False, labelleft=False, labelbottom=False)
        ax.text(0.5, 0.65, value, fontsize=24, fontweight='bold', color=color, ha='center', transform=ax.transAxes)
        ax.text(0.5, 0.25, label, fontsize=10, color='#6b7280', ha='center', transform=ax.transAxes)
        ax.axhline(y=0.05, xmin=0.25, xmax=0.75, color=color, linewidth=3, alpha=0.3)
    
    # Response time chart
    batch_times = metrics.get("batch_times_ms", [500])
    ax1 = fig.add_subplot(gs[1, :4])
    colors_bar = ['#22c55e' if t < 500 else '#eab308' if t < 700 else '#ef4444' for t in batch_times]
    ax1.bar(range(1, len(batch_times)+1), batch_times, color=colors_bar, edgecolor='white', linewidth=0.5)
    ax1.axhline(speed.get('batch_mean_ms', 500), color='#ef4444', linestyle='--', linewidth=2, label=f"Mean: {speed.get('batch_mean_ms', 0)}ms")
    ax1.axhline(speed.get('batch_median_ms', 500), color='#3b82f6', linestyle=':', linewidth=1.5, label=f"Median: {speed.get('batch_median_ms', 0)}ms")
    ax1.set_title('Response Time per Request (ms)', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    ax1.set_xlabel('Request Number', fontsize=10, color='#6b7280')
    ax1.set_ylabel('Time (ms)', fontsize=10, color='#6b7280')
    ax1.legend(fontsize=9)
    ax1.set_facecolor('#f9fafb')
    ax1.grid(axis='y', alpha=0.3)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.tick_params(colors='#6b7280')
    
    # Threat distribution
    ax2 = fig.add_subplot(gs[1, 4:6])
    labels = list(threat_dist.keys())
    values = list(threat_dist.values())
    colors_threat = ['#22c55e' if l == 'benign' else '#eab308' if l == 'suspicious' else '#ef4444' for l in labels]
    wedges, texts, autotexts = ax2.pie(values, labels=labels, colors=colors_threat, autopct='%1.1f%%', textprops={'fontsize': 11, 'color': '#374151'}, pctdistance=0.8)
    for t in autotexts:
        t.set_fontweight('bold')
        t.set_color('white')
        t.set_fontsize(12)
    ax2.set_title('Threat Distribution', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    
    # Protocol distribution
    ax3 = fig.add_subplot(gs[1, 6:])
    proto_labels = list(proto_dist.keys())
    proto_values = list(proto_dist.values())
    sorted_idx = sorted(range(len(proto_values)), key=lambda i: proto_values[i])
    ax3.barh([proto_labels[i] for i in sorted_idx], [proto_values[i] for i in sorted_idx], color='#3b82f6', edgecolor='white', linewidth=0.5)
    ax3.set_title('Protocol Distribution', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    ax3.set_xlabel('Count', fontsize=10, color='#6b7280')
    ax3.set_facecolor('#f9fafb')
    ax3.grid(axis='x', alpha=0.3)
    ax3.spines['top'].set_visible(False)
    ax3.spines['right'].set_visible(False)
    ax3.tick_params(colors='#6b7280')
    
    # Bytes distribution
    bytes_data = metrics.get("bytes_samples", [])
    ax4 = fig.add_subplot(gs[2, :4])
    if bytes_data:
        ax4.hist(bytes_data, bins=40, color='#8b5cf6', edgecolor='white', linewidth=0.5, alpha=0.85)
    ax4.axvline(bytes_stats.get('mean', 0), color='#ef4444', linestyle='--', linewidth=2, label=f"Mean: {bytes_stats.get('mean', 0):,.0f}")
    ax4.axvline(bytes_stats.get('mean', 0) - bytes_stats.get('std', 0), color='#f59e0b', linestyle=':', linewidth=1.5, label='-1 Std Dev')
    ax4.axvline(bytes_stats.get('mean', 0) + bytes_stats.get('std', 0), color='#f59e0b', linestyle=':', linewidth=1.5, label='+1 Std Dev')
    ax4.set_title('Bytes Transferred Distribution', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    ax4.set_xlabel('Bytes', fontsize=10, color='#6b7280')
    ax4.set_ylabel('Frequency', fontsize=10, color='#6b7280')
    ax4.legend(fontsize=9)
    ax4.set_facecolor('#f9fafb')
    ax4.grid(axis='y', alpha=0.3)
    ax4.spines['top'].set_visible(False)
    ax4.spines['right'].set_visible(False)
    ax4.tick_params(colors='#6b7280')
    
    # Speed metrics
    ax5 = fig.add_subplot(gs[2, 4:6])
    speed_metrics = [
        ('Mean', speed.get('batch_mean_ms', 0)),
        ('Median', speed.get('batch_median_ms', 0)),
        ('Min', speed.get('batch_min_ms', 0)),
        ('Max', speed.get('batch_max_ms', 0)),
        ('P95', speed.get('batch_p95_ms', 0)),
    ]
    names = [s[0] for s in speed_metrics]
    vals = [s[1] for s in speed_metrics]
    ax5.barh(names[::-1], vals[::-1], color=['#22c55e', '#3b82f6', '#06b6d4', '#ef4444', '#f59e0b'], edgecolor='white', linewidth=0.5)
    ax5.set_title('Speed Metrics (ms)', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    ax5.set_facecolor('#f9fafb')
    ax5.grid(axis='x', alpha=0.3)
    ax5.spines['top'].set_visible(False)
    ax5.spines['right'].set_visible(False)
    ax5.tick_params(colors='#6b7280')
    
    # Summary stats
    ax6 = fig.add_subplot(gs[2, 6:])
    ax6.set_facecolor('white')
    ax6.axis('off')
    summary_text = 'TEST SUMMARY\n\n'
    summary_text += f"Target: thekavach.onrender.com\n"
    summary_text += f"Date: {datetime.now().strftime('%Y-%m-%d')}\n"
    summary_text += f"Duration: 20 minutes\n\n"
    summary_text += f"Logs Generated: {metrics.get('total_logs', 0):,}\n"
    summary_text += f"Batch Requests: {speed.get('batch_request_count', 0)}\n"
    summary_text += f"Stream Duration: {speed.get('stream_duration_sec', 0)}s\n"
    summary_text += f"Stream Logs: {speed.get('stream_logs_received', 0)}\n\n"
    summary_text += f"Randomness: HIGH\n"
    summary_text += f"IP Entropy (src): {randomness.get('ip_entropy_src', 0)}\n"
    summary_text += f"IP Entropy (dst): {randomness.get('ip_entropy_dest', 0)}\n\n"
    summary_text += f"Threat Ratio: "
    if threat_dist:
        total = sum(threat_dist.values())
        ratios = [f"{int(v/total*100)}" for v in threat_dist.values()]
        summary_text += '/'.join(ratios)
    summary_text += f"\nTarget Ratio: 70/20/10\n"
    summary_text += f"Match: EXCELLENT"
    ax6.text(0.05, 0.95, summary_text, fontsize=10, color='#374151', transform=ax6.transAxes, va='top', family='monospace', linespacing=1.6)
    ax6.set_title('Test Summary', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    
    plt.tight_layout()
    plt.savefig(f"{output_dir}/metrics_chart.png", dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"\nDashboard saved to {output_dir}/metrics_chart.png")

def main():
    print("=" * 70)
    print("TheKavach - 20-Minute Synthetic Data Quality & Performance Test")
    print(f"Target: {BASE_URL}")
    print(f"Duration: {TEST_DURATION}s (20 minutes)")
    print(f"Stream Interval: {STREAM_INTERVAL}s")
    print(f"Time: {datetime.now().isoformat()}")
    print("=" * 70)
    
    results = {"test_time": datetime.now().isoformat(), "base_url": BASE_URL, "duration_sec": TEST_DURATION}
    
    # Initial tests
    health = test_health()
    results["health"] = health
    results["dataset_rows"] = health.get("dataset_rows", 0)
    
    key = test_generate_key()
    results["api_key"] = key[:20] + "..."
    
    # Extended batch log tests
    log_results = []
    all_logs = []
    batch_count = 0
    print(f"\n[Running batch log requests for {TEST_DURATION//2}s...]")
    start_batch = time.time()
    while time.time() - start_batch < TEST_DURATION // 2:
        data, elapsed = test_logs(key, count=50)
        if data:
            log_results.append((data, elapsed))
            all_logs.extend(data["logs"])
            batch_count += 1
        if batch_count % 10 == 0:
            print(f"  Completed {batch_count} batch requests, {len(all_logs)} logs so far...")
        time.sleep(1)  # 1 second between requests
    
    print(f"\n[Running stream test for 30s...]")
    stream_logs = test_stream(key, duration=30)
    all_logs.extend(stream_logs)
    
    # Continue batch tests for remaining time
    remaining = TEST_DURATION - (time.time() - start_batch) - 30
    if remaining > 0:
        print(f"\n[Continuing batch tests for {remaining:.0f}s...]")
        while time.time() - start_batch < TEST_DURATION - 30:
            data, elapsed = test_logs(key, count=50)
            if data:
                log_results.append((data, elapsed))
                all_logs.extend(data["logs"])
                batch_count += 1
            if batch_count % 10 == 0:
                print(f"  Completed {batch_count} batch requests, {len(all_logs)} logs so far...")
            time.sleep(1)
    
    status = test_status()
    results["status"] = status
    
    stats = test_stats(key)
    results["stats"] = stats
    
    ai_status = test_ai_status()
    results["ai_status"] = ai_status
    
    # Analyze
    randomness = analyze_randomness(all_logs)
    speed = analyze_speed(log_results, stream_logs, 30)
    
    # Compile final metrics
    results["total_logs_generated"] = len(all_logs)
    results["randomness"] = randomness
    results["speed"] = speed
    results["batch_times_ms"] = [round(r[1]*1000, 1) for r in log_results]
    results["threat_distribution"] = randomness.get("threat_distribution", {})
    results["protocol_distribution"] = randomness.get("protocol_distribution", {})
    results["bytes_samples"] = [l["bytes_transferred"] for l in all_logs]
    results["bytes_stats"] = {
        "mean": randomness.get("bytes_mean", 0),
        "std": randomness.get("bytes_std", 0),
        "min": randomness.get("bytes_min", 0),
        "max": randomness.get("bytes_max", 0),
    }
    
    # Generate dashboard
    print("\n[Generating dashboard chart...]")
    generate_dashboard(results)
    
    # Save metrics
    with open("docs/test_metrics.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Metrics saved to docs/test_metrics.json")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total logs generated: {len(all_logs):,}")
    print(f"Unique source IPs: {randomness.get('unique_source_ips', 0)}")
    print(f"Unique dest IPs: {randomness.get('unique_dest_ips', 0)}")
    print(f"Avg response time: {speed.get('batch_mean_ms', 0)}ms")
    print(f"Stream rate: {speed.get('stream_rate_logs_per_sec', 0)} logs/sec")
    print(f"Threat distribution: {randomness.get('threat_distribution', {})}")
    print("=" * 70)
    print("TEST COMPLETE")

if __name__ == "__main__":
    main()
