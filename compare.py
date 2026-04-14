from itertools import product
from typing import List, Set, Dict, Tuple, Any

# --------- Domains ----------
DIGITS = set("0123456789")
DIALABLE_NON_DIGITS = set("*#")
DIALABLE_ALL = DIGITS | DIALABLE_NON_DIGITS

# --------- Errors ----------
class PatternSyntaxError(ValueError):
    """Raised when an advertised pattern has invalid syntax."""

# --------- Parser / Expander ----------
def _parse_bracket_token(token: str) -> List[str]:
    """
    Parse bracket expression like [6-9] or [^2-4].
    - Ranges allowed: digits 0-9; letters A-D (rare but allowed as literals).
    - Single members allowed: 0-9, A-D, *, #.
    - Negation applies ONLY to the digits domain 0-9 (e.g., [^2-4] => {0,1,5,6,7,8,9}).
      Any non-digit members in a negated set are ignored for the negation.
    """
    assert token.startswith('[') and token.endswith(']'), "Invalid bracket token"
    inner = token[1:-1]
    if not inner:
        raise PatternSyntaxError("Empty [] is not allowed")

    negated = inner.startswith('^')
    if negated:
        inner = inner[1:]
        if not inner:
            raise PatternSyntaxError("[^] requires at least one member or range")

    members: Set[str] = set()
    i = 0
    while i < len(inner):
        ch = inner[i]
        # Range?
        if i + 2 < len(inner) and inner[i + 1] == '-':
            start, end = inner[i], inner[i + 2]
            if start.isdigit() and end.isdigit():
                for d in range(int(start), int(end) + 1):
                    members.add(str(d))
            else:
                raise PatternSyntaxError(
                    f"Unsupported range '{start}-{end}'. Use 0-9 or A-D."
                )
            i += 3
            continue

        # Single member
        if ch.isdigit() or ch in "ABCD*#":
            members.add(ch)
            i += 1
        else:
            raise PatternSyntaxError(f"Invalid character '{ch}' in []")

    if negated:
        # Apply negation over digits only
        allowed = DIGITS - (members & DIGITS)
    else:
        allowed = members

    if not allowed:
        raise PatternSyntaxError("[] resolved to an empty set")

    return sorted(allowed)

def _tokenize_core(p: str) -> Tuple[List[List[str]], bool, bool]:
    """
    Tokenize everything except the final '%' or '!' (handled as flags).
    Returns:
      choices: list of per-position choices
      ends_with_percent: bool
      ends_with_bang: bool
    """
    if not p:
        raise PatternSyntaxError("Empty pattern")

    ends_with_percent = p.endswith('%')
    ends_with_bang = p.endswith('!')

    if ends_with_percent and ends_with_bang:
        raise PatternSyntaxError("Pattern cannot end with both '%' and '!'")

    # Strip the trailing flag if present
    if ends_with_percent or ends_with_bang:
        p = p[:-1]

    choices: List[List[str]] = []
    i = 0

    # Optional leading '+'
    if p.startswith('+'):
        choices.append(['+'])
        i = 1

    while i < len(p):
        ch = p[i]
        if ch == 'X':
            choices.append(sorted(DIGITS))  # X = 0-9
            i += 1
        elif ch in DIALABLE_ALL:
            choices.append([ch])
            i += 1
        elif ch == '[':
            j = p.find(']', i + 1)
            if j == -1:
                raise PatternSyntaxError("Unclosed '[' in pattern")
            token = p[i:j+1]
            choices.append(_parse_bracket_token(token))
            i = j + 1
        elif ch == '+':
            # '+' only allowed at position 0 (handled above)
            raise PatternSyntaxError("Literal '+' is only allowed at the first position")
        else:
            raise PatternSyntaxError(f"Unsupported character '{ch}' in pattern")

    return choices, ends_with_percent, ends_with_bang

def expand_advertised_pattern(
    pattern: str,
    *,
    max_results: int
) -> List[str]:
    """
    Expand a CUCM Advertised Pattern into a list of strings:
      - Fully enumerates all positions (literals, X, [..]/[^..]).
      - If the pattern ends with '%', returns base + base+1digit (or +1 dialable if configured).
      - If the pattern ends with '!', returns expanded prefixes with a literal '!' appended.
      - Raises PatternSyntaxError for syntax errors.
      - Guards with max_results to avoid accidental blow-ups.
    """
    choices, ends_with_percent, ends_with_bang = _tokenize_core(pattern)

    # Compute base expansion
    total = 1
    for c in choices:
        total *= len(c)
        if total > max_results:
            raise ValueError(
                f"Expansion would create {total} results (> max_results={max_results}). "
                "Narrow the pattern or increase max_results."
            )

    base = [''.join(chars) for chars in product(*choices)]

    # Trailing '%'
    if ends_with_percent:
        tail_set = sorted(DIGITS)
        total_with_percent = len(base) * (1 + len(tail_set))
        if total_with_percent > max_results:
            raise ValueError(
                f"Expansion would create {total_with_percent} results (> max_results={max_results}). "
                "Consider increasing max_results."
            )
        extended = base[:]  # include base (no extra char)
        for b in base:
            for t in tail_set:
                extended.append(b + t)
        return extended

    # Trailing '!' -> return prefixes + '!'
    if ends_with_bang:
        return [b + '!' for b in base]

    return base

# --------- Conflict Detection ----------
def split_expanded(expanded: List[str]) -> Tuple[Set[str], List[str]]:
    """Split expanded results into finite set (no '!') and open-ended prefixes (ending with '!')."""
    finite = {s for s in expanded if not s.endswith('!')}
    prefixes = [s[:-1] for s in expanded if s.endswith('!')]  # strip the '!' for simpler checks
    return finite, prefixes

def conflicts_between(expanded_a: List[str], expanded_b: List[str]) -> Dict[str, Any]:
    """
    Determine conflicts between two expanded pattern result lists.
    Returns dict with:
      - 'finite_finite': sorted list of exact-number conflicts (strings)
      - 'finite_vs_prefix': sorted list of numbers from A that start with a prefix from B
      - 'prefix_vs_finite': sorted list of numbers from B that start with a prefix from A
      - 'prefix_prefix': sorted list of tuples (pa, pb) where pa or pb is a prefix of the other
    """
    finite_a, pref_a = split_expanded(expanded_a)
    finite_b, pref_b = split_expanded(expanded_b)

    # Finite vs finite
    ff = sorted(finite_a & finite_b)

    # Finite vs prefix (A finite vs B prefix)
    fvpb = sorted({n for n in finite_a for p in pref_b if n.startswith(p)})

    # Prefix vs finite (A prefix vs B finite)
    pvfa = sorted({n for n in finite_b for p in pref_a if n.startswith(p)})

    # Prefix vs prefix (any prefix starts with the other)
    pp = set()
    for pa in pref_a:
        for pb in pref_b:
            if pa.startswith(pb) or pb.startswith(pa):
                pp.add((min(pa, pb), max(pa, pb)))
    pp_list = sorted(pp)

    return {
        "finite_finite": ff,
        "finite_vs_prefix": fvpb,
        "prefix_vs_finite": pvfa,
        "prefix_prefix": pp_list,
    }

def _total_conflict_count(result: Dict[str, Any]) -> int:
    """Return total number of conflicts across all categories for a pairwise result."""
    return (
        len(result.get("finite_finite", [])) +
        len(result.get("finite_vs_prefix", [])) +
        len(result.get("prefix_vs_finite", [])) +
        len(result.get("prefix_prefix", []))
    )

def _summarize_pair(
    cluster_a: str, pat_a: str, exp_a: List[str],
    cluster_b: str, pat_b: str, exp_b: List[str],
    *, max_samples: int = 20
) -> Dict[str, Any] | None:
    """
    Build a compact summary for a pair of patterns.
    Returns None if no conflicts.

    NOTE: This version merges all sample values into a single list 'samples_all'.
    For prefix-prefix samples, renders as 'PA! ↔ PB!'.
    """
    res = conflicts_between(exp_a, exp_b)
    total = _total_conflict_count(res)
    if total == 0:
        return None

    # Build a single merged sample list in a deterministic order.
    samples_all: List[str] = []

    # finite_finite (exact numbers)
    samples_all.extend(res["finite_finite"][:max_samples])

    # finite_vs_prefix (numbers from A that match B’s prefixes)
    samples_all.extend(res["finite_vs_prefix"][:max_samples])

    # prefix_vs_finite (numbers from B that match A’s prefixes)
    samples_all.extend(res["prefix_vs_finite"][:max_samples])

    # prefix_prefix (render as readable pairs "PA! ↔ PB!")
    if res["prefix_prefix"]:
        pp_rendered = [f"{a}! ↔ {b}!" for a, b in res["prefix_prefix"][:max_samples]]
        samples_all.extend(pp_rendered)

    summary: Dict[str, Any] = {
        "cluster_a": cluster_a,
        "pattern_a": pat_a,
        "cluster_b": cluster_b,
        "pattern_b": pat_b,
        "samples": samples_all,  # <--- merged samples here
    }
    return summary


def compare(
    cluster_patterns: Dict[str, List[str]],
    *,
    max_results: int,
    max_samples: int = 20
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Compare all advertised patterns across clusters.

    Returns:
      (within_cluster_conflicts, between_cluster_conflicts)

    Each conflict entry now includes:
      - 'cluster_a', 'pattern_a', 'cluster_b', 'pattern_b'
      - 'counts' (per-category + total)
      - 'samples_all' (single merged list of sample strings)
    """
    # Expand once and cache
    expanded: Dict[Tuple[str, str], List[str]] = {}
    for cluster, pats in cluster_patterns.items():
        for p in pats:
            key = (cluster, p)
            if key in expanded:
                continue
            expanded[key] = expand_advertised_pattern(
                p, max_results=max_results
            )

    within: List[Dict[str, Any]] = []
    between: List[Dict[str, Any]] = []

    # WITHIN each cluster
    for cluster, pats in cluster_patterns.items():
        for i in range(len(pats)):
            for j in range(i + 1, len(pats)):
                pa, pb = pats[i], pats[j]
                sa = _summarize_pair(
                    cluster, pa, expanded[(cluster, pa)],
                    cluster, pb, expanded[(cluster, pb)],
                    max_samples=max_samples
                )
                if sa:
                    # For within-cluster entries, you might prefer a shorter shape.
                    # We'll add 'cluster' (single) and drop 'cluster_b' to reduce duplication.
                    sa["cluster"] = cluster
                    sa.pop("cluster_b", None)
                    within.append(sa)

    # BETWEEN clusters
    cluster_names = list(cluster_patterns.keys())
    for ci in range(len(cluster_names)):
        for cj in range(ci + 1, len(cluster_names)):
            ca, cb = cluster_names[ci], cluster_names[cj]
            for pa in cluster_patterns[ca]:
                for pb in cluster_patterns[cb]:
                    sb = _summarize_pair(
                        ca, pa, expanded[(ca, pa)],
                        cb, pb, expanded[(cb, pb)],
                        max_samples=max_samples
                    )
                    if sb:
                        between.append(sb)

    return within, between