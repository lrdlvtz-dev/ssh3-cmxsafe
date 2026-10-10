#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    printf 'usage: %s <version> <source-commit> <output-dir>\n' "$0" >&2
    exit 2
fi

version="$1"
source_commit="$2"
output_dir="$3"

if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]]; then
    printf 'invalid release version: %s\n' "$version" >&2
    exit 2
fi
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'source commit must be a full lowercase Git SHA-1\n' >&2
    exit 2
fi

for tool in go git jq sha256sum tar gzip; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'required tool not found: %s\n' "$tool" >&2
        exit 2
    }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
actual_commit="$(git -C "$repo_root" rev-parse HEAD)"
if [[ "$actual_commit" != "$source_commit" ]]; then
    printf 'source commit %s does not match checked-out commit %s\n' "$source_commit" "$actual_commit" >&2
    exit 2
fi

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
work_dir="$(mktemp -d -t ssh3-cmxsafe-release.XXXXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

source_date_epoch="$(git -C "$repo_root" show -s --format=%ct "$source_commit")"
export SOURCE_DATE_EPOCH="$source_date_epoch"

artifacts_json='[]'
for arch in amd64 arm64; do
    stage="$work_dir/ssh3-cmxsafe_${version}_linux_${arch}"
    mkdir -p "$stage"

    (
        cd "$repo_root"
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            go build -trimpath -buildvcs=true -tags disable_password_auth \
            -ldflags='-buildid= -s -w' -o "$stage/ssh3" ./cmd/ssh3
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            go build -trimpath -buildvcs=true -tags disable_password_auth \
            -ldflags='-buildid= -s -w' -o "$stage/ssh3-server" ./cmd/ssh3-server
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            go build -trimpath -buildvcs=true -tags disable_password_auth \
            -ldflags='-buildid= -s -w' -o "$stage/ssh3-cmxsafe-cert" ./cmd/ssh3-cmxsafe-cert
    )

    install -m 0644 "$repo_root/README.md" "$stage/README.md"
    install -m 0644 "$repo_root/LICENSE" "$stage/LICENSE"
    install -m 0644 "$repo_root/NOTICE.cmxsafe" "$stage/NOTICE.cmxsafe"

    artifact_name="ssh3-cmxsafe_${version}_linux_${arch}.tar.gz"
    tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
        -C "$work_dir" -cf - "$(basename "$stage")" | gzip -n > "$output_dir/$artifact_name"
    artifact_sha256="$(sha256sum "$output_dir/$artifact_name" | awk '{print $1}')"
    artifacts_json="$(jq -c \
        --arg name "$artifact_name" \
        --arg arch "$arch" \
        --arg sha256 "$artifact_sha256" \
        '. + [{name:$name, os:"linux", arch:$arch, sha256:$sha256}]' \
        <<<"$artifacts_json")"
done

go_version="$(go env GOVERSION)"
jq -n \
    --arg version "$version" \
    --arg commit "$source_commit" \
    --arg go_version "$go_version" \
    --argjson artifacts "$artifacts_json" \
    '{
      schema_version: 1,
      component: "ssh3-cmxsafe",
      release_version: $version,
      source: {
        repository: "https://github.com/lrdlvtz-dev/ssh3-cmxsafe",
        commit: $commit
      },
      build: {
        go_version: $go_version,
        source_date_epoch: env.SOURCE_DATE_EPOCH,
        password_authentication: false
      },
      protocol: {
        name: "SSH3",
        version: "3.0_alpha-00",
        status: "experimental"
      },
      capabilities: [
        "cmxsafe-direct-gateway-trust-v1",
        "cmxsafe-active-next-certificate-rotation",
        "cmxsafe-long-lived-gateway-certificate-v1",
        "cmxsafe-authorized-identity-restrictions-v1",
        "cmxsafe-uid-helper-protocol-v2",
        "tcp-forwarding",
        "udp-forwarding"
      ],
      runtime_dependencies: [{
        component: "ssh3-uid-helper",
        protocol_version: 2,
        required_for: ["identity-scoped-tcp-udp-forwarding"]
      }],
      artifacts: $artifacts
    }' > "$output_dir/cmxsafe-component.json"

(
    cd "$output_dir"
    sha256sum ./*.tar.gz cmxsafe-component.json > SHA256SUMS
)
