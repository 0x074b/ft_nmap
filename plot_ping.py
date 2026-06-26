#!/usr/bin/env python3
"""
Plot the distribution of ping round-trip times for every IP in a host file.

Each host is pinged COUNT times; the per-reply RTTs are collected and drawn as
one box (plus the individual samples) per host, so you can see spread, median
and outliers side by side. Hosts are sorted by median RTT; unreachable hosts
(no replies) are listed separately rather than plotted as empty boxes.

Usage:
    python3 plot_ping.py                         # reads ./ip.txt
    python3 plot_ping.py -f ip.txt -c 30 -w 16 -o ping.png
"""

import argparse
import concurrent.futures
import platform
import re
import statistics
import subprocess
import sys

# "time=12.3 ms" and the occasional "time<1 ms" sub-millisecond form.
RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def read_ips(path):
    """Read one host per line; skip blanks/comments, drop duplicates (keep order)."""
    seen = []
    with open(path) as f:
        for line in f:
            host = line.strip()
            if not host or host.startswith("#"):
                continue
            if host not in seen:
                seen.append(host)
    return seen


def ping_host(host, count, timeout):
    """Ping `host` `count` times; return the list of RTTs in ms (may be empty)."""
    if platform.system() == "Darwin":
        # macOS: -W is per-packet timeout in milliseconds.
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), host]
    else:
        # Linux iputils: -W is per-reply timeout in seconds.
        cmd = ["ping", "-n", "-c", str(count), "-W", str(timeout), host]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=count * (timeout + 1) + 5,
        ).stdout
    except subprocess.TimeoutExpired:
        return []
    return [float(m) for m in RTT_RE.findall(out)]


def gather(hosts, count, timeout, workers):
    """Ping all hosts concurrently; return {host: [rtts]} preserving input order."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(ping_host, h, count, timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            host = futs[fut]
            results[host] = fut.result()
            got = len(results[host])
            print(f"  {host:<16} {got}/{count} replies", file=sys.stderr)
    return {h: results[h] for h in hosts}  # restore input order


def plot(results, count, output):
    import matplotlib.pyplot as plt

    alive = {h: r for h, r in results.items() if r}
    dead = [h for h, r in results.items() if not r]
    if not alive:
        print("No host answered any ping; nothing to plot.", file=sys.stderr)
        return

    # Sort by median RTT so the chart reads left (fast) to right (slow).
    order = sorted(alive, key=lambda h: statistics.median(alive[h]))
    data = [alive[h] for h in order]

    fig, ax = plt.subplots(figsize=(max(8, 0.45 * len(order)), 6))
    positions = range(1, len(order) + 1)
    ax.boxplot(data, positions=positions, showfliers=False, widths=0.6)

    # Overlay the actual samples (jittered) so the distribution is visible.
    import random
    for pos, rtts in zip(positions, data):
        xs = [pos + random.uniform(-0.18, 0.18) for _ in rtts]
        ax.scatter(xs, rtts, s=10, alpha=0.4, color="tab:blue")

    loss = [100.0 * (1 - len(alive[h]) / count) for h in order]
    labels = [f"{h}\n({l:.0f}% loss)" if l else h for h, l in zip(order, loss)]
    ax.set_xticks(list(positions))
    ax.set_xticklabels(labels, rotation=90, fontsize=8)
    ax.set_ylabel("RTT (ms)")
    ax.set_title(f"Ping RTT distribution ({count} pings/host, sorted by median)")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    if dead:
        ax.text(0.01, 0.98, "Unreachable: " + ", ".join(dead),
                transform=ax.transAxes, va="top", fontsize=8, color="tab:red")
    fig.tight_layout()
    fig.savefig(output, dpi=120)
    print(f"Wrote {output}", file=sys.stderr)
    if dead:
        print("Unreachable hosts: " + ", ".join(dead), file=sys.stderr)


def plot_histogram(results, bins, output):
    """Histogram of every individual ping RTT, with a normal curve overlaid."""
    import math

    import matplotlib.pyplot as plt

    rtts = [v for samples in results.values() for v in samples]
    if len(rtts) < 2:
        print("Not enough samples for a histogram.", file=sys.stderr)
        return
    mean = statistics.mean(rtts)
    sd = statistics.pstdev(rtts)

    fig, ax = plt.subplots(figsize=(9, 6))
    counts, edges, _ = ax.hist(rtts, bins=bins, color="tab:blue",
                               alpha=0.7, edgecolor="white")
    # Overlay a normal curve scaled to counts (n * bin_width * pdf), so you can
    # eyeball how close the distribution is to a bell.
    if sd > 0:
        width = edges[1] - edges[0]
        scale = len(rtts) * width / (sd * math.sqrt(2 * math.pi))
        step = (edges[-1] - edges[0]) / 200
        xs = [edges[0] + i * step for i in range(201)]
        ys = [scale * math.exp(-0.5 * ((x - mean) / sd) ** 2) for x in xs]
        ax.plot(xs, ys, color="tab:red", lw=2,
                label=f"normal fit  μ={mean:.2f}  σ={sd:.2f} ms")
        ax.legend()
    ax.set_xlabel("RTT (ms)")
    ax.set_ylabel("number of pings")
    ax.set_title(f"RTT distribution over all pings (n={len(rtts)})")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(output, dpi=120)
    print(f"Wrote {output}", file=sys.stderr)


def plot_avg_histogram(results, bins, output):
    """Histogram of each host's average RTT: x = mean RTT, y = number of hosts."""
    import math

    import matplotlib.pyplot as plt

    means = [statistics.mean(s) for s in results.values() if s]
    if len(means) < 2:
        print("Not enough hosts for an average-RTT histogram.", file=sys.stderr)
        return
    mean = statistics.mean(means)
    sd = statistics.pstdev(means)

    fig, ax = plt.subplots(figsize=(9, 6))
    counts, edges, _ = ax.hist(means, bins=bins, color="tab:green",
                               alpha=0.7, edgecolor="white")
    if sd > 0:
        width = edges[1] - edges[0]
        scale = len(means) * width / (sd * math.sqrt(2 * math.pi))
        step = (edges[-1] - edges[0]) / 200
        xs = [edges[0] + i * step for i in range(201)]
        ys = [scale * math.exp(-0.5 * ((x - mean) / sd) ** 2) for x in xs]
        ax.plot(xs, ys, color="tab:red", lw=2,
                label=f"normal fit  μ={mean:.2f}  σ={sd:.2f} ms")
        ax.legend()
    ax.set_xlabel("average RTT per host (ms)")
    ax.set_ylabel("number of hosts")
    ax.set_title(f"Distribution of per-host average RTT (n={len(means)} hosts)")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(output, dpi=120)
    print(f"Wrote {output}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-f", "--file", default="ip.txt", help="host list (default ip.txt)")
    ap.add_argument("-c", "--count", type=int, default=20, help="pings per host")
    ap.add_argument("-w", "--workers", type=int, default=16, help="parallel pings")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="per-reply timeout (s)")
    ap.add_argument("-o", "--output", default="ping_dist.png", help="per-host box plot PNG")
    ap.add_argument("--hist-output", default="ping_hist.png", help="per-ping RTT histogram PNG")
    ap.add_argument("--avg-output", default="ping_avg_hist.png", help="per-host average-RTT histogram PNG")
    ap.add_argument("--bins", type=int, default=40, help="histogram bins")
    args = ap.parse_args()

    hosts = read_ips(args.file)
    if not hosts:
        sys.exit(f"No hosts found in {args.file}")
    print(f"Pinging {len(hosts)} hosts x{args.count}...", file=sys.stderr)
    results = gather(hosts, args.count, args.timeout, args.workers)
    plot(results, args.count, args.output)
    plot_histogram(results, args.bins, args.hist_output)
    plot_avg_histogram(results, args.bins, args.avg_output)


if __name__ == "__main__":
    main()
