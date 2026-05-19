import time
import json
import random
import math
import torch
import numpy as np
from datetime import datetime
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_recall_fscore_support

import sys
import os
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from models.inference import LogNormalizer, get_ai_engine

HF_MODEL = "OMCHOKSI108/TheKavach"
TEST_DURATION = 1200
OUTPUT_DIR = "docs"

PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'ICMP', 'DNS']
ACTIONS = ['allowed', 'blocked', 'denied', 'dropped']
LOG_TYPES = ['firewall', 'ids', 'application']
PATHS_SAFE = ['/index.html', '/api/data', '/static/css', '/images/logo.png', '/docs/readme', '/health', '/status']
PATHS_RISKY = ['/admin/config', '/wp-login.php', '/.env', '/backup.sql', '/shell.php', '/config/db.yml']
PATHS_AUTH = ['/login', '/auth/token', '/secure/admin', '/api/auth']
AGENTS_SAFE = ['Mozilla/5.0 Chrome/120', 'Mozilla/5.0 Firefox/119', 'Mozilla/5.0 Safari/17', 'curl/8.0']
AGENTS_SCANNER = ['nmap scripting engine', 'sqlmap/1.7', 'nikto/2.1.6', 'masscan/1.3', 'zap/2.14']
BYTES_RANGE = (64, 65535)

def generate_test_log(threat_label=None):
    if threat_label is None:
        r = random.random()
        threat_label = 'benign' if r < 0.70 else 'suspicious' if r < 0.90 else 'malicious'

    if threat_label == 'benign':
        protocol = random.choice(PROTOCOLS)
        action = random.choice(['allowed', 'allowed', 'allowed', 'blocked'])
        path = random.choice(PATHS_SAFE)
        agent = random.choice(AGENTS_SAFE)
        log_type = random.choice(LOG_TYPES)
    elif threat_label == 'suspicious':
        protocol = random.choice(['TCP', 'HTTP', 'HTTPS', 'DNS'])
        action = random.choice(['blocked', 'denied', 'allowed'])
        path = random.choice(PATHS_AUTH + PATHS_RISKY[:2])
        agent = random.choice(AGENTS_SAFE + AGENTS_SCANNER[:1])
        log_type = random.choice(LOG_TYPES)
    else:
        protocol = random.choice(['TCP', 'HTTP', 'HTTPS'])
        action = random.choice(['blocked', 'denied', 'dropped'])
        path = random.choice(PATHS_RISKY)
        agent = random.choice(AGENTS_SCANNER)
        log_type = random.choice(LOG_TYPES)

    bytes_val = random.randint(*BYTES_RANGE)
    return {
        'protocol': protocol,
        'action': action,
        'user_agent': agent,
        'request_path': path,
        'bytes_transferred': bytes_val,
        'log_type': log_type,
        'source_ip': f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        'dest_ip': f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
    }, threat_label

def run_evaluation():
    print("=" * 70)
    print("TheKavach - AI Model Evaluation (20-Min Test)")
    print(f"Model: {HF_MODEL}")
    print(f"Time: {datetime.now().isoformat()}")
    print("=" * 70)

    print("\nLoading model from HuggingFace...")
    ai = get_ai_engine(hf_model=HF_MODEL)
    print("Model loaded successfully!")

    results = {
        'test_time': datetime.now().isoformat(),
        'model': HF_MODEL,
        'duration_sec': TEST_DURATION,
    }

    all_preds = []
    all_labels = []
    all_confidences = []
    all_response_times = []
    threat_counts = Counter()
    protocol_counts = Counter()
    bytes_list = []
    per_class_metrics = {}

    start_time = time.time()
    batch_count = 0
    print(f"\nRunning evaluation for {TEST_DURATION}s...")

    while time.time() - start_time < TEST_DURATION:
        log, true_label = generate_test_log()
        t0 = time.time()
        try:
            result = ai.analyze_log(log)
            elapsed = time.time() - t0
            pred_label = result['threat']
            confidence = result['confidence']

            all_preds.append(pred_label)
            all_labels.append(true_label)
            all_confidences.append(confidence)
            all_response_times.append(elapsed)
            threat_counts[pred_label] += 1
            protocol_counts[log['protocol']] += 1
            bytes_list.append(log['bytes_transferred'])
            batch_count += 1

            if batch_count % 100 == 0:
                elapsed_total = time.time() - start_time
                rate = batch_count / elapsed_total
                print(f"  {batch_count} logs analyzed in {elapsed_total:.0f}s ({rate:.1f} logs/sec)")
        except Exception as e:
            print(f"  Error: {e}")

        time.sleep(0.05)

    total_time = time.time() - start_time
    print(f"\nEvaluation complete: {batch_count} logs in {total_time:.1f}s")

    accuracy = accuracy_score(all_labels, all_preds)
    precision, recall, f1, support = precision_recall_fscore_support(all_labels, all_preds, average=None, labels=['benign', 'suspicious', 'malicious'])
    precision_macro = precision_recall_fscore_support(all_labels, all_preds, average='macro', labels=['benign', 'suspicious', 'malicious'])
    cm = confusion_matrix(all_labels, all_preds, labels=['benign', 'suspicious', 'malicious'])

    for i, label in enumerate(['benign', 'suspicious', 'malicious']):
        per_class_metrics[label] = {
            'precision': round(float(precision[i]), 4),
            'recall': round(float(recall[i]), 4),
            'f1_score': round(float(f1[i]), 4),
            'support': int(support[i])
        }

    print(f"\n=== OVERALL METRICS ===")
    print(f"  Accuracy: {accuracy:.4f}")
    print(f"  Macro Precision: {precision_macro[0]:.4f}")
    print(f"  Macro Recall: {precision_macro[1]:.4f}")
    print(f"  Macro F1: {precision_macro[2]:.4f}")
    print(f"  Avg response time: {np.mean(all_response_times)*1000:.1f}ms")

    results['total_analyzed'] = batch_count
    results['accuracy'] = round(float(accuracy), 4)
    results['macro_precision'] = round(float(precision_macro[0]), 4)
    results['macro_recall'] = round(float(precision_macro[1]), 4)
    results['macro_f1'] = round(float(precision_macro[2]), 4)
    results['per_class'] = per_class_metrics
    results['confusion_matrix'] = cm.tolist()
    results['threat_distribution_predicted'] = dict(threat_counts)
    results['protocol_distribution'] = dict(protocol_counts)
    results['response_times_ms'] = [round(t*1000, 2) for t in all_response_times]
    results['stats'] = {
        'mean_ms': round(float(np.mean(all_response_times)*1000), 2),
        'median_ms': round(float(np.median(all_response_times)*1000), 2),
        'min_ms': round(float(np.min(all_response_times)*1000), 2),
        'max_ms': round(float(np.max(all_response_times)*1000), 2),
        'p95_ms': round(float(np.percentile(all_response_times, 95)*1000), 2),
        'throughput_logs_per_sec': round(batch_count / total_time, 2),
    }

    print("\n[Generating evaluation plots...]")
    generate_plots(all_labels, all_preds, all_confidences, all_response_times, cm, accuracy, results)

    with open(f"{OUTPUT_DIR}/model_eval.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Results saved to {OUTPUT_DIR}/model_eval.json")

def generate_plots(all_labels, all_preds, all_confidences, all_response_times, cm, accuracy, results):
    labels = ['benign', 'suspicious', 'malicious']
    colors = ['#22c55e', '#eab308', '#ef4444']

    fig = plt.figure(figsize=(22, 14), facecolor='white')
    gs = gridspec.GridSpec(3, 8, figure=fig, hspace=0.35, wspace=0.3)
    fig.suptitle('TheKavach - AI Model Evaluation Report (20-Min Test)', fontsize=20, fontweight='bold', color='#1a1a2e', y=0.98)

    stats = results['stats']
    kpi_data = [
        ('Accuracy', f"{results['accuracy']*100:.1f}%", '#22c55e'),
        ('Macro F1', f"{results['macro_f1']:.3f}", '#3b82f6'),
        ('Total Analyzed', f"{results['total_analyzed']:,}", '#8b5cf6'),
        ('Throughput', f"{stats['throughput_logs_per_sec']}/s", '#f59e0b'),
        ('Avg Latency', f"{stats['mean_ms']:.0f}ms", '#ef4444'),
        ('P95 Latency', f"{stats['p95_ms']:.0f}ms", '#06b6d4'),
        ('Precision', f"{results['macro_precision']:.3f}", '#10b981'),
        ('Recall', f"{results['macro_recall']:.3f}", '#ec4899'),
    ]
    for i, (label, value, color) in enumerate(kpi_data):
        ax = fig.add_subplot(gs[0, i])
        ax.set_facecolor('white')
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.tick_params(left=False, bottom=False, labelleft=False, labelbottom=False)
        ax.text(0.5, 0.65, value, fontsize=22, fontweight='bold', color=color, ha='center', transform=ax.transAxes)
        ax.text(0.5, 0.25, label, fontsize=9, color='#6b7280', ha='center', transform=ax.transAxes)
        ax.axhline(y=0.05, xmin=0.25, xmax=0.75, color=color, linewidth=3, alpha=0.3)

    ax1 = fig.add_subplot(gs[1, :3])
    im = ax1.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax1.set_title('Confusion Matrix', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    ax1.set_xticks(range(3))
    ax1.set_yticks(range(3))
    ax1.set_xticklabels(labels, fontsize=11)
    ax1.set_yticklabels(labels, fontsize=11)
    ax1.set_xlabel('Predicted', fontsize=11, color='#6b7280')
    ax1.set_ylabel('True', fontsize=11, color='#6b7280')
    thresh = cm.max() / 2.
    for i in range(3):
        for j in range(3):
            ax1.text(j, i, f"{cm[i, j]}", ha="center", va="center",
                     color="white" if cm[i, j] > thresh else "black", fontsize=14, fontweight='bold')
    plt.colorbar(im, ax=ax1, fraction=0.046, pad=0.04)

    ax2 = fig.add_subplot(gs[1, 3:6])
    per_class = results['per_class']
    x = np.arange(3)
    width = 0.25
    prec_vals = [per_class[l]['precision'] for l in labels]
    rec_vals = [per_class[l]['recall'] for l in labels]
    f1_vals = [per_class[l]['f1_score'] for l in labels]
    bars1 = ax2.bar(x - width, prec_vals, width, label='Precision', color='#3b82f6', edgecolor='white')
    bars2 = ax2.bar(x, rec_vals, width, label='Recall', color='#22c55e', edgecolor='white')
    bars3 = ax2.bar(x + width, f1_vals, width, label='F1-Score', color='#f59e0b', edgecolor='white')
    ax2.set_title('Per-Class Performance Metrics', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=11)
    ax2.set_ylim(0, 1.1)
    ax2.legend(fontsize=10)
    ax2.set_facecolor('#f9fafb')
    ax2.grid(axis='y', alpha=0.3)
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    for bar in bars1 + bars2 + bars3:
        height = bar.get_height()
        ax2.annotate(f'{height:.2f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

    ax3 = fig.add_subplot(gs[2, :4])
    ax3.hist(all_response_times, bins=50, color='#8b5cf6', edgecolor='white', linewidth=0.5, alpha=0.85)
    ax3.axvline(np.mean(all_response_times), color='#ef4444', linestyle='--', linewidth=2, label=f"Mean: {stats['mean_ms']:.0f}ms")
    ax3.axvline(np.percentile(all_response_times, 95), color='#f59e0b', linestyle=':', linewidth=1.5, label=f"P95: {stats['p95_ms']:.0f}ms")
    ax3.set_title('Response Time Distribution', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)
    ax3.set_xlabel('Time (seconds)', fontsize=10, color='#6b7280')
    ax3.set_ylabel('Frequency', fontsize=10, color='#6b7280')
    ax3.legend(fontsize=9)
    ax3.set_facecolor('#f9fafb')
    ax3.grid(axis='y', alpha=0.3)
    ax3.spines['top'].set_visible(False)
    ax3.spines['right'].set_visible(False)

    ax4 = fig.add_subplot(gs[2, 4:])
    ax4.set_facecolor('white')
    ax4.axis('off')
    summary = 'EVALUATION SUMMARY\n\n'
    summary += f"Model: {HF_MODEL}\n"
    summary += f"Date: {datetime.now().strftime('%Y-%m-%d')}\n"
    summary += f"Duration: {results['duration_sec']}s ({results['duration_sec']/60:.0f} min)\n\n"
    summary += f"Total Logs Analyzed: {results['total_analyzed']:,}\n"
    summary += f"Accuracy: {results['accuracy']*100:.1f}%\n"
    summary += f"Macro F1: {results['macro_f1']:.3f}\n"
    summary += f"Throughput: {stats['throughput_logs_per_sec']} logs/sec\n\n"
    summary += 'PER-CLASS METRICS\n'
    for label in labels:
        m = per_class[label]
        summary += f"\n{label.upper()}:\n"
        summary += f"  Precision: {m['precision']:.3f}\n"
        summary += f"  Recall:    {m['recall']:.3f}\n"
        summary += f"  F1-Score:  {m['f1_score']:.3f}\n"
        summary += f"  Support:   {m['support']:,}\n"
    summary += f"\nCONFIDENCE STATS\n"
    summary += f"  Mean: {np.mean(all_confidences):.3f}\n"
    summary += f"  Median: {np.median(all_confidences):.3f}\n"
    summary += f"  Min: {np.min(all_confidences):.3f}\n"
    summary += f"  Max: {np.max(all_confidences):.3f}\n"
    ax4.text(0.05, 0.98, summary, fontsize=9, color='#374151', transform=ax4.transAxes, va='top', family='monospace', linespacing=1.5)
    ax4.set_title('Summary', fontsize=14, fontweight='bold', color='#1a1a2e', pad=12)

    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/model_eval_chart.png", dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Evaluation chart saved to {OUTPUT_DIR}/model_eval_chart.png")

if __name__ == "__main__":
    run_evaluation()
