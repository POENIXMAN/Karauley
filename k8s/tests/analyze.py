#!/usr/bin/env python3

import json
import sys
import os
import argparse
from collections import Counter, defaultdict
from pathlib import Path


def _is_attack_domain(domain, attack_domain_suffix="attack.test"):
    if not domain or domain.startswith("<") or not isinstance(domain, str):
        return False
    d = domain.lower()
    suffix = attack_domain_suffix.lower()
    if d == suffix:
        return True
    if d.endswith("." + suffix):
        return True
    if "." + suffix + "." in d:
        return True
    if d.endswith("." + suffix + ".lan"):
        return True
    return False


def classify_by_pod(pod_name, attack_namespace="attack"):
    if not pod_name or pod_name == "unknown":
        return "unknown"
    if "/" in pod_name:
        ns = pod_name.split("/")[0]
    else:
        return "legit"

    if ns == attack_namespace or ns.startswith(f"{attack_namespace}-"):
        parts = pod_name.split("/")[1] if "/" in pod_name else pod_name
        for tool in ["iodine", "dnscat", "exfil", "dns2tcp", "sliver"]:
            if tool in parts.lower():
                return f"attack:{tool}"
        return "attack:unknown"
    return "legit"


def classify_event(pod_name, domain, gt_by_domain=False, attack_namespace="attack", attack_domain_suffix="attack.test"):
    if gt_by_domain and domain:
        if _is_attack_domain(domain, attack_domain_suffix):
            d = domain.lower()
            if "exfil" in d or "dnsexfil" in d:
                return "attack:exfil"
            if "c2." in d or "dnscat" in d:
                return "attack:dnscat"
            if "t." in d and "attack.test" in d:  # iodine t.attack.test
                return "attack:iodine"
            return "attack:unknown"
        return "legit"
    return classify_by_pod(pod_name, attack_namespace)


def analyze_file(jsonl_path, attack_namespace="attack", score_threshold=None, gt_by_domain=False, attack_domain_suffix="attack.test"):
    tp = fp = fn = tn = 0
    fp_domains = Counter()
    fn_domains = Counter()
    tp_domains = Counter()
    score_dist = {"tp": [], "fp": [], "tn": [], "fn": []}
    reason_counts = Counter()
    threat_type_counts = Counter()

    first_attack_ts = None
    first_alert_ts = None
    events_total = 0
    parse_errors = 0
    unparseable_count = 0

    with open(jsonl_path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue

            events_total += 1
            pod = ev.get("pod", "unknown")
            domain = ev.get("domain", "")
            if domain == "<unparseable>" or (domain and str(domain).startswith("<")):
                unparseable_count += 1
            score = ev.get("score", 0)
            reasons = ev.get("reasons", [])
            threat_type = ev.get("threat_type")

            if score_threshold is not None:
                is_suspicious = score >= score_threshold
            else:
                is_suspicious = ev.get("suspicious", False)

            label = classify_event(pod, domain, gt_by_domain=gt_by_domain, attack_namespace=attack_namespace, attack_domain_suffix=attack_domain_suffix)
            is_attack = label.startswith("attack:")

            if is_attack:
                ts = ev.get("ts", 0)
                if ts and (first_attack_ts is None or ts < first_attack_ts):
                    first_attack_ts = ts
                if is_suspicious and ts and (first_alert_ts is None or ts < first_alert_ts):
                    first_alert_ts = ts

            if is_attack and is_suspicious:
                tp += 1
                score_dist["tp"].append(score)
                tp_domains[domain] += 1
                for r in reasons:
                    reason_counts[r] += 1
                if threat_type:
                    threat_type_counts[threat_type] += 1
            elif is_attack and not is_suspicious:
                fn += 1
                score_dist["fn"].append(score)
                fn_domains[domain] += 1
            elif not is_attack and is_suspicious:
                fp += 1
                score_dist["fp"].append(score)
                fp_domains[domain] += 1
                for r in reasons:
                    reason_counts[f"FP:{r}"] += 1
            else:
                tn += 1
                score_dist["tn"].append(score)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    detection_latency_ns = None
    if first_attack_ts and first_alert_ts:
        detection_latency_ns = first_alert_ts - first_attack_ts

    def avg(lst):
        return sum(lst) / len(lst) if lst else 0.0

    unparseable_pct = (unparseable_count / events_total * 100.0) if events_total else 0.0
    return {
        "file": str(jsonl_path),
        "events_total": events_total,
        "parse_errors": parse_errors,
        "unparseable_count": unparseable_count,
        "unparseable_pct": unparseable_pct,
        "gt_by_domain": gt_by_domain,
        "attack_domain_suffix": attack_domain_suffix,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "score_threshold": score_threshold,
        "detection_latency_s": (detection_latency_ns / 1e9) if detection_latency_ns else None,
        "score_mean_tp": avg(score_dist["tp"]),
        "score_mean_fp": avg(score_dist["fp"]),
        "score_mean_fn": avg(score_dist["fn"]),
        "score_mean_tn": avg(score_dist["tn"]),
        "fp_domains": fp_domains.most_common(20),
        "fn_domains": fn_domains.most_common(20),
        "tp_domains": tp_domains.most_common(20),
        "reason_counts": reason_counts.most_common(30),
        "threat_type_counts": threat_type_counts.most_common(10),
        "score_dist": score_dist,
    }


def print_report(result):
    f = result
    name = os.path.basename(f["file"])
    threshold_info = f" (пересчёт с threshold={f['score_threshold']})" if f["score_threshold"] else ""
    gt_info = f" [GT по домену: *.{f.get('attack_domain_suffix', 'attack.test')}]" if f.get("gt_by_domain") else ""

    print(f"\n{'='*70}")
    print(f"  {name}{threshold_info}{gt_info}")
    print(f"{'='*70}")
    print(f"  Events: {f['events_total']}  (parse errors: {f['parse_errors']})")
    if f.get("unparseable_count") is not None:
        print(f"  Unparseable (domain): {f['unparseable_count']}  ({f.get('unparseable_pct', 0):.2f}%)")
    print()

    print(f"  {'Confusion Matrix':^40}")
    print(f"  {'':>20} {'Suspicious':>12} {'Clean':>12}")
    print(f"  {'Attack (GT)':>20} {'TP=' + str(f['tp']):>12} {'FN=' + str(f['fn']):>12}")
    print(f"  {'Legit (GT)':>20} {'FP=' + str(f['fp']):>12} {'TN=' + str(f['tn']):>12}")
    print()

    print(f"  Precision:  {f['precision']:.4f}")
    print(f"  Recall:     {f['recall']:.4f}")
    print(f"  F1:         {f['f1']:.4f}")
    print(f"  FPR:        {f['fpr']:.6f}  ({f['fpr']*100:.3f}%)")
    print()

    if f["detection_latency_s"] is not None:
        print(f"  Detection Latency: {f['detection_latency_s']:.2f}s")
    print(f"  Score mean (TP): {f['score_mean_tp']:.2f}")
    print(f"  Score mean (FP): {f['score_mean_fp']:.2f}")
    print(f"  Score mean (FN): {f['score_mean_fn']:.2f}")
    print()

    if f["fp_domains"]:
        print("  Top FP domains:")
        for domain, count in f["fp_domains"][:10]:
            print(f"    {domain:<50} {count:>5}")
        print()

    if f["fn_domains"]:
        print("  Top FN domains (missed attacks):")
        for domain, count in f["fn_domains"][:10]:
            print(f"    {domain:<50} {count:>5}")
        print()

    if f["reason_counts"]:
        print("  Detector reasons fired:")
        for reason, count in f["reason_counts"][:15]:
            print(f"    {reason:<45} {count:>5}")
        print()

    if f["threat_type_counts"]:
        print("  Threat types (TP):")
        for tt, count in f["threat_type_counts"]:
            print(f"    {tt:<30} {count:>5}")
    print()


def print_summary_table(results):
    print(f"\n{'='*110}")
    print(f"  СВОДНАЯ ТАБЛИЦА")
    print(f"{'='*110}")
    header = f"  {'File':<25} {'Events':>7} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>7} {'Prec':>7} {'Recall':>7} {'F1':>7} {'FPR':>8} {'Latency':>8}"
    print(header)
    print(f"  {'-'*106}")
    for r in results:
        name = os.path.basename(r["file"]).replace(".jsonl", "")
        lat = f"{r['detection_latency_s']:.1f}s" if r["detection_latency_s"] else "—"
        print(f"  {name:<25} {r['events_total']:>7} {r['tp']:>5} {r['fp']:>5} {r['fn']:>5} {r['tn']:>7} "
              f"{r['precision']:>7.4f} {r['recall']:>7.4f} {r['f1']:>7.4f} {r['fpr']:>8.5f} {lat:>8}")
    print(f"{'='*110}")


def save_results_json(result, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    name = Path(result["file"]).stem

    safe_result = {k: v for k, v in result.items() if k != "score_dist"}
    with open(os.path.join(output_dir, f"{name}_metrics.json"), "w") as f:
        json.dump(safe_result, f, indent=2, ensure_ascii=False)

    with open(os.path.join(output_dir, f"{name}_score_dist.json"), "w") as f:
        json.dump(result["score_dist"], f)


def main():
    parser = argparse.ArgumentParser(description="Анализ JSONL-логов dns-tunnel-monitor")
    parser.add_argument("files", nargs="+", help="JSONL файл(ы) для анализа")
    parser.add_argument("--threshold", type=int, default=None,
                        help="Пересчитать с другим score threshold (по умолчанию — из лога)")
    parser.add_argument("--attack-ns", default="attack",
                        help="Namespace атакующих подов (default: attack)")
    parser.add_argument("--gt-by-domain", action="store_true",
                        help="Ground truth по домену: *.attack.test → attack (убирает артефакт CoreDNS FP)")
    parser.add_argument("--attack-domain", default="attack.test",
                        help="Суффикс атакующего домена при --gt-by-domain (default: attack.test)")
    parser.add_argument("--summary", action="store_true",
                        help="Вывести только сводную таблицу")
    parser.add_argument("--save", action="store_true",
                        help="Сохранить результаты в results/ как JSON")
    args = parser.parse_args()

    results = []
    for fpath in args.files:
        if not os.path.exists(fpath):
            print(f"WARNING: file not found: {fpath}", file=sys.stderr)
            continue
        result = analyze_file(fpath, args.attack_ns, args.threshold, gt_by_domain=args.gt_by_domain, attack_domain_suffix=args.attack_domain)
        results.append(result)
        if not args.summary:
            print_report(result)
        if args.save:
            save_results_json(result, os.path.join(os.path.dirname(fpath), "analysis"))

    if len(results) > 1 or args.summary:
        print_summary_table(results)


if __name__ == "__main__":
    main()
