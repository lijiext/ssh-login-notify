#!/bin/sh
set -eu

pattern='自动|直接|默认|仅|只|建议|可以|需要|必须|同时|当前|目前|通常|仍然|仍|已经|立即|快速|轻松|显著|完全|始终|尽量|务必|可能|大约|然后|如果|如需'

matches=$(grep -R -n -E --include='*.md' --exclude-dir='.git' -- "$pattern" . || true)
if [ -n "$matches" ]; then
    echo "$matches"
    echo "documentation style check failed" >&2
    exit 1
fi
