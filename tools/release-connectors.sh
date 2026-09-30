#!/usr/bin/env bash
# Publish a GitHub release for every connector package that does not have one yet.
#
#   tools/release-connectors.sh              create the missing releases (needs gh + GH_TOKEN)
#   DRY_RUN=1 tools/release-connectors.sh    only print what would be created
#
# A package is connectors/<name>-v<x.y.z>.tgz. For each one found in the history of HEAD:
#   tag      <name>-v<x.y.z>, on the last commit in which the .tgz existed (so the tag's tree
#            holds exactly the file attached to the release)
#   asset    the .tgz as committed
#   notes    the message of the commit that added the .tgz, plus the package's SHA-256
#
# Idempotent: a version that already has a release is skipped, so it is safe to run on every
# push and to re-run after a failure. Releases are created oldest version first, which leaves
# the newest one marked "Latest".
#
# To ship a new connector version: bump app_version, build the package into connectors/, and
# merge to main with a commit message that says what changed. The workflow does the rest.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

DRY_RUN=${DRY_RUN:-0}
pattern='^connectors/([a-z0-9_]+)-v([0-9]+\.[0-9]+\.[0-9]+)\.tgz$'
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mapfile -t packages < <(
    git log --diff-filter=A --name-only --format= HEAD -- 'connectors/*.tgz' |
        grep -E "$pattern" | sort -uV
)
if [ ${#packages[@]} -eq 0 ]; then
    echo "No connector packages found in the history of HEAD." >&2
    exit 1
fi

failed=0
for path in "${packages[@]}"; do
    [[ $path =~ $pattern ]]
    name=${BASH_REMATCH[1]}
    version=${BASH_REMATCH[2]}
    tag="$name-v$version"

    if [ "$DRY_RUN" != 1 ] && gh release view "$tag" >/dev/null 2>&1; then
        echo "skip    $tag (release exists)"
        continue
    fi

    added_sha=$(git log --diff-filter=A --format=%H -1 HEAD -- "$path")
    built_sha=$(git log --diff-filter=AM --format=%H -1 HEAD -- "$path")
    asset="$work/$(basename "$path")"
    git show "$built_sha:$path" >"$asset"

    # The version inside the package is what SOAR compares on install: it must match the file name.
    if ! meta=$(tar -xzOf "$asset" "$name/$name.json" |
        python3 -c 'import json, sys; d = json.load(sys.stdin); print(d["app_version"]); print(d["name"])'); then
        echo "::error::$path: cannot read $name/$name.json from the package"
        failed=1
        continue
    fi
    inner_version=$(sed -n 1p <<<"$meta")
    inner_name=$(sed -n 2p <<<"$meta")
    if [ "$inner_version" != "$version" ]; then
        echo "::error::$path: file name says $version but the package's app_version is $inner_version"
        failed=1
        continue
    fi

    title="$inner_name connector v$version"
    if [ "$DRY_RUN" = 1 ]; then
        echo "create  $tag  \"$title\"  tag on ${built_sha:0:7}, notes from ${added_sha:0:7}, asset $(basename "$asset") ($(stat -c %s "$asset") bytes)"
        continue
    fi

    notes="$work/$tag.md"
    {
        git log -1 --format=%B "$added_sha" | grep -v -E '^(Co-Authored-By|Claude-Session):' | cat -s
        printf '\n---\n\n**Package:** `%s`  \n**SHA-256:** `%s`  \n**Built from commit:** %s\n\n' \
            "$(basename "$asset")" "$(sha256sum "$asset" | cut -d' ' -f1)" "$built_sha"
        printf 'Install it from **Apps > Install App** in the SOAR UI. SOAR refuses a package whose `app_version` is not higher than the installed one.\n'
    } >"$notes"

    echo "create  $tag"
    if ! gh release create "$tag" "$asset" --target "$built_sha" --title "$title" --notes-file "$notes"; then
        echo "::error::could not create the release for $tag"
        failed=1
    fi
done

exit "$failed"
