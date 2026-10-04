"""Command-line interface for the ThreatInt pipeline."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from threatint.config import load_config
from threatint.pipeline import run_pipeline
from threatint.reporting import (
    render_console,
    write_campaigns_csv,
    write_indicators_csv,
    write_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatint",
        description="Collect, cross-verify, classify and cluster threat indicators.",
    )
    parser.add_argument("--config", help="Path to config.yaml (defaults to repo config).")
    parser.add_argument("--offline", action="store_true", help="Use bundled fixtures, never the network.")
    parser.add_argument("--labels", help="CSV of analyst labels (indicator,label) for supervised training.")
    parser.add_argument("--model-path", help="Where to save/load the trained classifier.")
    parser.add_argument("--use-saved-model", action="store_true", help="Load a previously trained model instead of retraining.")
    parser.add_argument("--no-train", action="store_true", help="Skip classifier training (verdicts stay UNKNOWN).")
    parser.add_argument("--corpus-size", type=int, default=1200, help="Synthetic bootstrap corpus size.")
    parser.add_argument("--out-json", help="Write full results as JSON to this path.")
    parser.add_argument("--out-indicators", help="Write indicators as CSV to this path.")
    parser.add_argument("--out-campaigns", help="Write campaigns as CSV to this path.")
    parser.add_argument("--top", type=int, default=15, help="Rows to show in the console report.")
    parser.add_argument("--quiet", action="store_true", help="Only emit the final report.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    try:
        result = run_pipeline(
            config=config,
            offline=args.offline,
            labels_path=args.labels,
            model_path=args.model_path,
            use_saved_model=args.use_saved_model,
            corpus_size=args.corpus_size,
            train_classifier=not args.no_train,
        )
    except Exception as exc:  # surface a clean error, keep traceback behind -v
        logging.getLogger("threatint").error("pipeline failed: %s", exc)
        if args.verbose:
            raise
        return 1

    print(render_console(result, top=args.top))

    if args.out_json:
        path = write_json(result, args.out_json)
        print(f"\nwrote JSON report      -> {path}")
    if args.out_indicators:
        path = write_indicators_csv(result, args.out_indicators)
        print(f"wrote indicators CSV   -> {path}")
    if args.out_campaigns:
        path = write_campaigns_csv(result, args.out_campaigns)
        print(f"wrote campaigns CSV    -> {path}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
