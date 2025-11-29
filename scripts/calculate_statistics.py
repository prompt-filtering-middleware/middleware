import json
from pathlib import Path
from collections import defaultdict

# File Paths
DATASET_PATH = Path(__file__).parent.parent.parent / "dataset" / "synthetic_prompt_dataset_filtered.json"
MISMATCHES_PATH = Path(__file__).parent.parent / "artifacts" / "mismatches.jsonl"
OUTPUT_PATH = Path(__file__).parent.parent / "artifacts" / "evaluation_statistics.json"

print("Loading dataset and mismatches")
print(f"Dataset: {DATASET_PATH}")
print(f"Mismatches: {MISMATCHES_PATH}")
print()

# Load Dataset
print("Step 1: Loading filtered dataset")
with open(DATASET_PATH, "r", encoding="utf-8") as f:
    dataset = json.load(f)

total_samples = len(dataset)
print(f"Total samples in dataset: {total_samples:,}")

# Count samples per category
category_counts = defaultdict(int)
label_counts = defaultdict(int)

for sample in dataset:
    category = sample["category"]
    label = sample["label"]
    category_counts[category] += 1
    label_counts[label] += 1

print(f"Unique categories: {len(category_counts)}")
print(f"Sensitive samples: {label_counts['sensitive']:,}")
print(f"Non-sensitive samples: {label_counts['non_sensitive']:,}")
print()

# Load Mismatches 
print("Step 2: Loading mismatches")
mismatches = []
with open(MISMATCHES_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            mismatches.append(json.loads(line))

total_failures = len(mismatches)
print(f"Total mismatches: {total_failures:,}")
print()

# Count failures per category
failures_by_category = defaultdict(int)
failure_types = defaultdict(int)

for mismatch in mismatches:
    expected_category = mismatch["expected_category"]
    expected_label = mismatch["expected_label"]
    actual_label = mismatch["actual_label"]
    
    failures_by_category[expected_category] += 1
    
    # Classify failure type
    if expected_label == "sensitive" and actual_label == "non_sensitive":
        failure_types["false_negative"] += 1
    elif expected_label == "non_sensitive" and actual_label == "sensitive":
        failure_types["false_positive"] += 1
    else:
        failure_types["other"] += 1

print("Step 3: Analyzing failure types ")
print(f"  False Negatives (missed sensitive): {failure_types['false_negative']:,}")
print(f"  False Positives (wrongly flagged): {failure_types['false_positive']:,}")
print(f"  Other mismatches: {failure_types['other']:,}")
print()

# Calculate Overall Statistics
print("Step 4: Calculating overall statistics")
total_successes = total_samples - total_failures
overall_accuracy = (total_successes / total_samples) * 100
overall_error_rate = (total_failures / total_samples) * 100

print(f"  Total Successes: {total_successes:,}")
print(f"  Total Failures: {total_failures:,}")
print(f"  Overall Accuracy: {overall_accuracy:.2f}%")
print(f"  Overall Error Rate: {overall_error_rate:.2f}%")
print()

# Calculate Per-Category Statistics
print("Step 5: Calculating per-category statistics")
category_stats = {}

for category in sorted(category_counts.keys()):
    total = category_counts[category]
    failures = failures_by_category.get(category, 0)
    successes = total - failures
    
    success_rate = (successes / total) * 100 if total > 0 else 0
    failure_rate = (failures / total) * 100 if total > 0 else 0
    
    category_stats[category] = {
        "total_samples": total,
        "successes": successes,
        "failures": failures,
        "success_rate": round(success_rate, 2),
        "failure_rate": round(failure_rate, 2),
        "detection_rate": round(success_rate, 2)  # Same as success rate
    }

# Sort categories by success rate 
sorted_categories = sorted(
    category_stats.items(),
    key=lambda x: x[1]["success_rate"],
    reverse=True
)

print("\nTop 10 Best Performing Categories:")
print(f"{'Category':<25} {'Total':>8} {'Success':>8} {'Failure':>8} {'Rate':>8}")
print("-" * 70)
for category, stats in sorted_categories[:10]:
    print(f"{category:<25} {stats['total_samples']:>8,} {stats['successes']:>8,} "
          f"{stats['failures']:>8,} {stats['success_rate']:>7.2f}%")

print("\nTop 10 Worst Performing Categories:")
print(f"{'Category':<25} {'Total':>8} {'Success':>8} {'Failure':>8} {'Rate':>8}")
print("-" * 70)
for category, stats in sorted_categories[-10:]:
    print(f"{category:<25} {stats['total_samples']:>8,} {stats['successes']:>8,} "
          f"{stats['failures']:>8,} {stats['success_rate']:>7.2f}%")

print()

# Calculate Binary Classification Metrics
print("Step 6: Calculating binary classification metrics")


# - True Positives (TP): Correctly identified as sensitive
# - True Negatives (TN): Correctly identified as non-sensitive
# - False Positives (FP): Non-sensitive marked as sensitive
# - False Negatives (FN): Sensitive marked as non-sensitive

# From the data:
sensitive_total = label_counts["sensitive"]
non_sensitive_total = label_counts["non_sensitive"]

# False negatives (from mismatches where expected=sensitive, actual=non_sensitive)
false_negatives = failure_types["false_negative"]

# False positives (from mismatches where expected=non_sensitive, actual=sensitive)
false_positives = failure_types["false_positive"]

# True positives: All sensitive samples minus false negatives
true_positives = sensitive_total - false_negatives

# True negatives: All non-sensitive samples minus false positives
true_negatives = non_sensitive_total - false_positives

# Calculate metrics
precision = (true_positives / (true_positives + false_positives)) * 100 if (true_positives + false_positives) > 0 else 0
recall = (true_positives / (true_positives + false_negatives)) * 100 if (true_positives + false_negatives) > 0 else 0
f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
specificity = (true_negatives / (true_negatives + false_positives)) * 100 if (true_negatives + false_positives) > 0 else 0

print(f"True Positives (TP): {true_positives:,}")
print(f"True Negatives (TN): {true_negatives:,}")
print(f"False Positives (FP): {false_positives:,}")
print(f"False Negatives (FN): {false_negatives:,}")
print()
print(f"Precision: {precision:.2f}%")
print(f"Recall (Sensitivity): {recall:.2f}%")
print(f"F1-Score: {f1_score:.2f}%")
print(f"Specificity: {specificity:.2f}%")
print()

# Save Results to JSON
print("Step 7: Saving results")

results = {
    "dataset_info": {
        "total_samples": total_samples,
        "unique_categories": len(category_counts),
        "sensitive_samples": label_counts["sensitive"],
        "non_sensitive_samples": label_counts["non_sensitive"]
    },
    "overall_performance": {
        "total_successes": total_successes,
        "total_failures": total_failures,
        "accuracy": round(overall_accuracy, 2),
        "error_rate": round(overall_error_rate, 2)
    },
    "binary_classification_metrics": {
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1_score": round(f1_score, 2),
        "specificity": round(specificity, 2)
    },
    "failure_analysis": {
        "false_negatives": failure_types["false_negative"],
        "false_positives": failure_types["false_positive"],
        "other_mismatches": failure_types["other"]
    },
    "per_category_performance": category_stats
}

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"Results saved to: {OUTPUT_PATH}")
print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total Samples: {total_samples:,}")
print(f"Accuracy: {overall_accuracy:.2f}%")
print(f"Precision: {precision:.2f}%")
print(f"Recall: {recall:.2f}%")
print(f"F1-Score: {f1_score:.2f}%")
print("=" * 70)

