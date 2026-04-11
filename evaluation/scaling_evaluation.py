"""
Scaling Evaluation for CyberRange ACL Verifier.

Runs the two-phase probe generator across N = {10, 25, 50, 100, 150, 200, 255}
tenants and plots:
  1. Probe count vs N (our approach vs naive exhaustive baseline)
  2. Probe count breakdown (positive, Phase 1, Phase 2) vs N
  3. Reduction factor vs N
  4. Phase 2 probe count vs k (violations) for fixed N=255
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np

from synthetic_data.generator import generate_synthetic_db
from acl_generator.generator import ACLGenerator
from probe_generator.two_phase_generator import TwoPhaseProbeGenerator

# --- Configuration ---
N_VALUES = [10, 25, 50, 100, 150, 200, 255]
HOST_IPS_PER_SUBNET = 254  # usable IPs in a /24
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def collect_data():
    """Run probe generator for each N and collect counts."""
    results = []

    for n in N_VALUES:
        db = generate_synthetic_db(num_students=n - 1, num_instructors=1)
        policy = ACLGenerator(db).generate()

        user_subnet_map = {}
        for user in db.get_active_users():
            subnet = db.get_subnet_for_user(user.id)
            if subnet:
                user_subnet_map[user.headscale_username] = subnet.subnet_cidr

        actual_n = len(user_subnet_map)
        gen = TwoPhaseProbeGenerator(policy, user_subnet_map)

        # Best case: no violations, Phase 2 never triggers
        probe_set_best = gen.generate(users_with_leaks=[])
        # Worst case: all users have violations
        probe_set_worst = gen.generate(users_with_leaks=list(user_subnet_map.keys()))

        positive = len(probe_set_best.positive_probes)
        phase1 = len(probe_set_best.phase1_probes)
        phase2_worst = len(probe_set_worst.phase2_probes)

        naive = HOST_IPS_PER_SUBNET * HOST_IPS_PER_SUBNET * actual_n * (actual_n - 1)

        results.append({
            'n': actual_n,
            'positive': positive,
            'phase1': phase1,
            'phase2_worst': phase2_worst,
            'total_best': positive + phase1,
            'total_worst': positive + phase1 + phase2_worst,
            'naive': naive,
            'reduction_best': naive / max(positive + phase1, 1),
            'reduction_worst': naive / max(positive + phase1 + phase2_worst, 1),
        })

        print(f"N={actual_n:3d} | best={positive+phase1:5d} | "
              f"worst={positive+phase1+phase2_worst:7d} | "
              f"naive={naive:>15,} | "
              f"reduction(best)={naive/(positive+phase1):>10,.0f}x")

    return results


def plot_all(results):
    """Generate all four plots in one figure."""
    ns = [r['n'] for r in results]
    positive = [r['positive'] for r in results]
    phase1 = [r['phase1'] for r in results]
    phase2_worst = [r['phase2_worst'] for r in results]
    total_best = [r['total_best'] for r in results]
    total_worst = [r['total_worst'] for r in results]
    naive = [r['naive'] for r in results]
    reduction_best = [r['reduction_best'] for r in results]
    reduction_worst = [r['reduction_worst'] for r in results]

    fig = plt.figure(figsize=(16, 12))
    fig.suptitle('CyberRange ACL Verifier — Scaling Evaluation', fontsize=14, fontweight='bold')
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.4, wspace=0.35)

    # --- Plot 1: Total probe count vs naive baseline (log scale) ---
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.semilogy(ns, naive, 'r-o', label='Naive exhaustive (H²×N(N-1))', linewidth=2)
    ax1.semilogy(ns, total_worst, 'b-s', label='Our approach — worst case (all violated)', linewidth=2)
    ax1.semilogy(ns, total_best, 'g-^', label='Our approach — best case (no violations)', linewidth=2)
    ax1.set_xlabel('Number of tenants (N)')
    ax1.set_ylabel('Probe count (log scale)')
    ax1.set_title('Total Probe Count vs Naive Baseline')
    ax1.legend(fontsize=8)
    ax1.grid(True, alpha=0.3)
    ax1.set_xticks(ns)

    # --- Plot 2: Probe count breakdown (stacked) ---
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.stackplot(ns, positive, phase1, phase2_worst,
                  labels=['Positive (2N)', 'Phase 1 (N)', 'Phase 2 worst case k(N-1)'],
                  colors=['#2ecc71', '#3498db', '#e74c3c'], alpha=0.8)
    ax2.set_xlabel('Number of tenants (N)')
    ax2.set_ylabel('Probe count')
    ax2.set_title('Probe Count Breakdown')
    ax2.legend(fontsize=8, loc='upper left')
    ax2.grid(True, alpha=0.3)
    ax2.set_xticks(ns)

    # --- Plot 3: Reduction factor vs N ---
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.plot(ns, [r / 1000 for r in reduction_best], 'g-^',
             label='Best case reduction (k=0)', linewidth=2)
    ax3.plot(ns, [r / 1000 for r in reduction_worst], 'b-s',
             label='Worst case reduction (k=N)', linewidth=2)
    ax3.set_xlabel('Number of tenants (N)')
    ax3.set_ylabel('Reduction factor (×1000)')
    ax3.set_title('Reduction Factor vs Naive Exhaustive Probing')
    ax3.legend(fontsize=8)
    ax3.grid(True, alpha=0.3)
    ax3.set_xticks(ns)

    # --- Plot 4: Phase 2 probe count vs k for N=255 ---
    ax4 = fig.add_subplot(gs[1, 1])
    n_fixed = 255
    k_values = list(range(0, n_fixed + 1, 10))
    phase2_counts = [k * (n_fixed - 1) for k in k_values]
    total_counts = [(2 * n_fixed + n_fixed + k * (n_fixed - 1)) for k in k_values]
    ax4.plot(k_values, phase2_counts, 'r-', label='Phase 2 probes k(N-1)', linewidth=2)
    ax4.plot(k_values, total_counts, 'b--', label='Total probes', linewidth=2)
    ax4.axhline(y=2 * n_fixed + n_fixed, color='g', linestyle=':', linewidth=2,
                label=f'Best case (3N={3*n_fixed})')
    ax4.set_xlabel('Users with violations (k)')
    ax4.set_ylabel('Probe count')
    ax4.set_title(f'Phase 2 Growth vs Violations (N={n_fixed})')
    ax4.legend(fontsize=8)
    ax4.grid(True, alpha=0.3)

    output_path = os.path.join(OUTPUT_DIR, 'scaling_evaluation.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"\nPlot saved to {output_path}")
    return output_path


if __name__ == "__main__":
    print("Running scaling evaluation...")
    print(f"{'N':>4} | {'Best':>5} | {'Worst':>7} | {'Naive':>15} | {'Reduction(best)':>15}")
    print("-" * 65)
    results = collect_data()
    output_path = plot_all(results)
    print("\nDone!")