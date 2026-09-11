#!/bin/sh
# What a scan would check for, before letting it check for anything.
#
# `--detection` sets a ceiling on what the engine may do to a target: naming
# ACTIVE_MUTATING lets in everything up to it. This is how you see what that
# actually is, on this build, without scanning anybody.
#
#     ZONDD=./target/debug/zondd sh examples/detections.sh
#     ZONDD=./target/debug/zondd sh examples/detections.sh DETECTION_CLASS_EXPLOIT
#
# There is nothing here but a line of JSON and `jq`, which is the point: the
# protocol needs no client, and a shell is a client.

set -eu

zondd=${ZONDD:-zondd}
ceiling=${1:-}

echo '{"id":1,"method":"detections"}' | "$zondd" --stdio --no-journal | jq -r --arg ceiling "$ceiling" '
  # Cheapest to the target first, which is the order a ceiling reads in.
  ["DETECTION_CLASS_DERIVED", "DETECTION_CLASS_PASSIVE", "DETECTION_CLASS_ACTIVE_BENIGN",
   "DETECTION_CLASS_ACTIVE_MUTATING", "DETECTION_CLASS_EXPLOIT", "DETECTION_CLASS_DOS"] as $order
  | (if $ceiling == "" then ($order | length) else ($order | index($ceiling)) end) as $limit
  | .result.detections
  | map(select(.class as $c | ($order | index($c)) <= $limit))
  | group_by(.class)
  | sort_by(.[0].class as $c | $order | index($c))
  | .[]
  | "\(.[0].class | ltrimstr("DETECTION_CLASS_"))  (\(length))",
    (.[] | "    \(.id)  \(.title)")
'
