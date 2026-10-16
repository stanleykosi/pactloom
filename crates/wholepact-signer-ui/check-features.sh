#!/usr/bin/env bash
# Build graph guard, not a substitute for runtime desktop qualification.
set -euo pipefail
cd "$(dirname "$0")/../.."
graph=$(cargo tree --locked --offline -p wholepact-signer-ui -e features)
if printf '%s\n' "$graph" | grep -E '(eframe feature "(default|accesskit|inspection|links|persistence|x11)"|egui-winit feature "(accesskit|links|x11)"|winit feature "x11"|glutin feature "(x11|glx)"|accesskit_unix v|egui_inspection v)'; then
    printf '%s\n' 'Refusing native signer graph: a forbidden activation or backend feature is enabled.' >&2
    exit 1
fi
grep -q 'eframe v0.36.2' <<< "$graph"
printf '%s\n' 'PASS: no eframe inspection/persistence/links, platform AccessKit activation or X11 window/input backend.'
printf '%s\n' 'AccessKit core types and X11 clipboard libraries remain in the graph; runtime clipboard audit is still required.'
