#!/usr/bin/env python3
"""Executable model of one packet becoming three modality replicas."""

import argparse


MODALITIES = (
    (2, 1, "IPv4", "s1-s11-s12-s2"),
    (3, 2, "IPv6", "s1-s21-s22-s2"),
    (4, 3, "SourceRouting", "s1-s31-s32-s2"),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sequence", type=int, default=1)
    parser.add_argument("--payload", default="class2-test")
    args = parser.parse_args()

    encoded = args.payload.encode("utf-8")
    if len(encoded) > 16:
        parser.error("UTF-8 payload must be at most 16 bytes")
    protected = encoded.ljust(16, b"\x00")

    print("INPUT count=1 sequence=%d protected_hex=%s" % (
        args.sequence,
        protected.hex(),
    ))
    for port, mode, name, path in MODALITIES:
        print(
            "REPLICA egress_port=%d modality_id=%d encapsulation=%s "
            "sequence=%d path=%s"
            % (port, mode, name, args.sequence, path)
        )
    print("SUMMARY input=1 replicas=3 same_sequence=yes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

