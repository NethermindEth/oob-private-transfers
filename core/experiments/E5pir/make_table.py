#!/usr/bin/env python3
"""Build E5 PIR tables from raw result files only.

Usage: make_table.py [RESULT_DIR ...]   (default: newest core/results/E5pir/<stamp>/ with pir-*.json;
                                          several dirs are merged, later dirs win per (m, layout))
Writes (LaTeX tabular BODIES only, no table env/caption):
  core/results/E5pir/e5_reads.tex      rows = epoch size m (16..2^16), default and best layout
  core/results/E5pir/e5_reads_ext.tex  2^20 rows (appendix)
  core/results/E5pir/e5_state.tex      server-side stored state vs raw epoch bytes
  core/results/E5pir/e5_amort.tex      cold bytes for R in {1,8,64} reads vs whole-epoch download
  core/results/E5pir/e5_crossover.tex  crossover epoch sizes m* (formula-derived, from crossover.json)
  core/results/E5pir/e5_summary.md     Markdown version of all of the above (+ p90/p99)
Runs marked contaminated (1-min load > 8 at start inside the lock, or > 12 at end) are skipped.
Units: B, kB = 10^3 B, MB = 10^6 B; times in ms.
"""
import glob, json, os, statistics, sys

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.abspath(os.path.join(HERE, "..", "..", "results", "E5pir"))
INCLUDE_CONTAMINATED = False  # --include-contaminated (never used for paper tables)


def fb(n):
    n = float(n)
    if n < 1e3:
        return f"{n:.0f} B"
    if n < 1e6:
        return f"{n/1e3:.1f} kB"
    if n < 1e9:
        return f"{n/1e6:.2f} MB"
    return f"{n/1e9:.2f} GB"


def pct(xs, q):
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def pow2(m):
    return f"$2^{{{m.bit_length()-1}}}$" if m & (m - 1) == 0 and m >= 1024 else f"{m:,}".replace(",", "{,}")


def load(dirs):
    runs = {}
    for d in dirs:
        for f in sorted(glob.glob(os.path.join(d, "pir-*.json"))):
            j = json.load(open(f))
            if "contaminated" in j:
                cont = j["contaminated"]
            else:  # runs from before the load gate existed: apply the same rule to the recorded loads
                cont = j["load_avg_at_submit"][0] > 8 or j.get("load_avg_at_end", [99])[0] > 12
            if cont and not INCLUDE_CONTAMINATED:
                print(f"skip (contaminated by load, kept as raw): {f}", file=sys.stderr)
                continue
            r = j.get("result")
            if not r:
                print(f"skip (error): {f}: {j.get('error')}", file=sys.stderr)
                continue
            mode = r.get("layout_mode") or "default"
            runs[(r["count"], mode)] = (f, j, r)
    return runs


def row(f, j, r):
    s = r["samples"]
    sz = r["sizes"]
    lay = r["layout"]
    ans = [x["answer_seconds"] * 1e3 for x in s]
    rec = [x["recover_seconds"] * 1e3 for x in s]
    qry = [x["query_seconds"] * 1e3 for x in s]
    # measured on-wire sizes (every sample), must equal the formula sizes
    qb = {x["query_bytes"] for x in s}
    ab = {x["answer_bytes"] for x in s}
    assert qb == {sz["query_bytes"]} and ab == {sz["answer_bytes"]}, f
    pub = r["client_load"]["public_bytes"]
    hint = r["client_load"]["hint_bytes"]
    q, a = sz["query_bytes"], sz["answer_bytes"]
    n = r["count"]
    whole = r["baselines"]["whole_epoch_download_bytes"]
    return dict(
        file=os.path.relpath(f, RES), m=n, mode=r.get("layout_mode") or "default", L=lay["l"], M=lay["m"], p=lay["p"],
        groups=lay["row_groups"], db=r["db_payload_bytes"], hint=hint, pub=pub, q=q, a=a,
        ans_med=statistics.median(ans), ans_p90=pct(ans, .9), ans_p99=pct(ans, .99), ans_min=min(ans), ans_max=max(ans),
        rec_med=statistics.median(rec), rec_p90=pct(rec, .9), rec_p99=pct(rec, .99),
        qry_med=statistics.median(qry), qry_p90=pct(qry, .9),
        nsamp=len(s), failures=r["failures"],
        cold1=pub + hint + q + a, warm=q + a, cold8=pub + hint + 8 * (q + a), cold64=pub + hint + 64 * (q + a),
        whole=whole, direct=r["baselines"]["direct_index_bytes"],
        setup_s=r["server_setup"]["setup_seconds"], hint_s=r["server_setup"]["hint_seconds"],
        client_setup_s=r["client_load"]["client_setup_seconds"], regenA_s=r["client_load"]["regen_A_seconds"],
        a_bytes=sz["a_bytes_if_downloaded"], packed=sz["packed_db_bytes"], unpacked=sz["db_matrix_bytes_unpacked"],
        rss_setup=r["rss_bytes"]["after_server_setup"], rss_timel=j.get("time_l", {}).get("max_rss_bytes"),
        scan_ms=statistics.median(r["baselines"]["whole_epoch_scan_seconds"]) * 1e3,
        load=j.get("load_avg_at_submit"),
    )


def same_layout(x, y):
    return x and y and (x["L"], x["M"], x["p"]) == (y["L"], y["M"], y["p"])


def cheaper(x):
    return "PIR" if x["cold1"] < x["whole"] else "download"


def tex_reads(rows):
    out = []
    for x in rows:
        lay = x["label"]
        out.append(" & ".join([
            pow2(x["m"]), lay, fb(x["db"]), fb(x["hint"]), fb(x["q"]), fb(x["a"]),
            f"{x['ans_med']:.3f}", f"{x['rec_med']:.3f}", fb(x["cold1"]), fb(x["warm"]), fb(x["whole"]),
            fb(x["direct"]), cheaper(x)]) + r" \\")
    return "\n".join(out) + "\n"


def main():
    global INCLUDE_CONTAMINATED
    dirs = [d for d in sys.argv[1:] if not d.startswith("--")]
    INCLUDE_CONTAMINATED = "--include-contaminated" in sys.argv
    if not dirs:
        cands = [d for d in sorted(glob.glob(os.path.join(RES, "2*"))) if glob.glob(os.path.join(d, "pir-*.json"))]
        dirs = cands[-1:]
    runs = load(dirs)
    R = {k: row(*v) for k, v in runs.items()}
    sizes = sorted({k[0] for k in R})
    main_rows, ext_rows = [], []
    for n in sizes:
        d, b = R.get((n, "default")), R.get((n, "best"))
        group = []
        if d and b and same_layout(d, b):
            d["label"] = "square = best"
            group = [d]
        else:
            if d:
                d["label"] = "square"
                group.append(d)
            if b:
                b["label"] = f"best ($m$={b['M']})" if b["M"] != n else "best (1 group)"
                group.append(b)
        (main_rows if n <= 65536 else ext_rows).extend(group)
    os.makedirs(RES, exist_ok=True)
    hdr = ("% cols: m & layout & DB & hint & query & answer & server answer ms (median) & client recover ms (median) & "
           "cold 1-read bytes (public.json+hint+q+a) & warm bytes/read (q+a) & whole-epoch download & direct index & cheaper\n"
           f"% generated by core/experiments/E5pir/make_table.py from {', '.join(os.path.relpath(d, RES) for d in dirs)}\n")
    open(os.path.join(RES, "e5_reads.tex"), "w").write(hdr + tex_reads(main_rows))
    open(os.path.join(RES, "e5_reads_ext.tex"), "w").write(hdr + tex_reads(ext_rows))
    allrows = main_rows + ext_rows
    # server-side stored state
    st = ["% cols: m & layout & raw epoch & packed DB matrix (server, answer) & hint (served) & public.json & A (not stored: seed) & (packed+hint)/raw & server setup s & peak RSS after setup\n"]
    for x in allrows:
        st.append(" & ".join([pow2(x["m"]), x["label"], fb(x["db"]), fb(x["packed"]), fb(x["hint"]), fb(x["pub"]),
                              f"0 ({fb(x['a_bytes'])} if stored)", f"{(x['packed']+x['hint'])/x['db']:.2f}",
                              f"{x['setup_s']:.3f}", fb(x["rss_setup"])]) + r" \\")
    open(os.path.join(RES, "e5_state.tex"), "w").write("\n".join(st) + "\n")
    am = ["% cols: m & layout & whole-epoch download & cold R=1 & cold R=8 & cold R=64 & warm per read (all: measured sizes)\n"]
    for x in allrows:
        am.append(" & ".join([pow2(x["m"]), x["label"], fb(x["whole"]), fb(x["cold1"]), fb(x["cold8"]), fb(x["cold64"]),
                              fb(x["warm"])]) + r" \\")
    open(os.path.join(RES, "e5_amort.tex"), "w").write("\n".join(am) + "\n")
    # crossover (formula-derived)
    cx = None
    for d in dirs:
        p = os.path.join(d, "crossover.json")
        if os.path.exists(p) and os.path.getsize(p):
            cx = json.load(open(p))["result"]
    lines = []
    if cx:
        lines.append("% cols: layout & reads R & first m where PIR cold bytes < m*736 & stable m* (PIR cheaper for all m >= m* up to scan limit) & PIR bytes at m* ; derived from exact size formulas\n")
        for c in cx["rows"]:
            lines.append(" & ".join([c["layout"], str(c["reads"]), f"{c['m_first']:,}".replace(",", "{,}"),
                                     f"{c['m_stable']:,}".replace(",", "{,}"), fb(c["pir_bytes_at_m_stable"])]) + r" \\")
        open(os.path.join(RES, "e5_crossover.tex"), "w").write("\n".join(lines) + "\n")
    # markdown
    md = [f"# E5 PIR results (generated from {', '.join(os.path.relpath(d, RES) for d in dirs)})\n",
          "Units: kB = 10^3 B, MB = 10^6 B. Cold = public.json + hint + R(q+a); warm = q+a per read. "
          "All reads byte-checked against the DB.\n",
          "| m | layout (l x m, p) | DB | hint | query | answer | server ans ms med/p90/p99 | recover ms med/p90/p99 | "
          "query-gen ms med | cold 1 read | warm/read | whole epoch | direct | cheaper | reads (fail) | load@submit |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for x in allrows:
        pc = lambda a, b, c: f"{a:.3f}/{b:.3f}/{c:.3f}" if x["nsamp"] >= 100 else f"{a:.3f} (n={x['nsamp']})"
        md.append(f"| {x['m']} | {x['label']} ({x['L']}x{x['M']}, p={x['p']}) | {fb(x['db'])} | {fb(x['hint'])} | {fb(x['q'])} | "
                  f"{fb(x['a'])} | {pc(x['ans_med'], x['ans_p90'], x['ans_p99'])} | {pc(x['rec_med'], x['rec_p90'], x['rec_p99'])} | "
                  f"{x['qry_med']:.3f} | {fb(x['cold1'])} | {fb(x['warm'])} | {fb(x['whole'])} | {fb(x['direct'])} | {cheaper(x)} | "
                  f"{x['nsamp']} ({x['failures']}) | {x['load'][0]:.1f} |")
    md += ["", "Server state and setup:", "",
           "| m | layout | raw epoch | packed DB | hint | public.json | A if downloaded (not stored) | server setup s | hint (DB*A) s | peak RSS after setup | client load s (regen A s) | whole-epoch scan ms |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for x in allrows:
        md.append(f"| {x['m']} | {x['label']} | {fb(x['db'])} | {fb(x['packed'])} | {fb(x['hint'])} | {fb(x['pub'])} | {fb(x['a_bytes'])} | "
                  f"{x['setup_s']:.3f} | {x['hint_s']:.3f} | {fb(x['rss_setup'])} | {x['client_setup_s']:.4f} ({x['regenA_s']:.4f}) | {x['scan_ms']:.2f} |")
    md += ["", "Reads per epoch (cold bytes):", "", "| m | layout | whole epoch | R=1 | R=8 | R=64 | warm/read |", "|---|---|---|---|---|---|---|"]
    for x in allrows:
        md.append(f"| {x['m']} | {x['label']} | {fb(x['whole'])} | {fb(x['cold1'])} | {fb(x['cold8'])} | {fb(x['cold64'])} | {fb(x['warm'])} |")
    if cx:
        md += ["", "Crossover (formula-derived from the implemented layouts; " + cx["kind"] + "):", "",
               "| layout | R | first m with PIR < download | stable m* | PIR bytes at m* |", "|---|---|---|---|---|"]
        for c in cx["rows"]:
            md.append(f"| {c['layout']} | {c['reads']} | {c['m_first']} | {c['m_stable']} | {fb(c['pir_bytes_at_m_stable'])} |")
    open(os.path.join(RES, "e5_summary.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
