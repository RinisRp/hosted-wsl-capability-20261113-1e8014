## Adapter source qualification branch

This branch only compiles and tests the generic Windows pipe adapter using Go1.26.11, Microsoft go-winio0.6.4 and x/sys0.49.0. It never starts the production adapter, WSL or Docker. Unit tests create nonce-owned local pipes and owned echo-test subprocesses. The workflow preserves unchanged source hashes, bounded diagnostics and formatter output without modifying source inputs. A successful source check does not establish real Docker transport, loopback behavior, private-project access, JIT or canonical acceptance.

The Microsoft library supplies retained first-handle ownership, remote-client rejection and byte-mode I/O cancellation. The adapter supplies explicit protected owner/System access, minimal child environments, bounded shutdown, independent endpoint closes, native-exit and pump accounting, and no payload logging. SDK Close completion is not reported as independently checked Win32 handle-close errors. Generated-descriptor tests are explicitly distinguished from actual ACL readback.

The sections below describe the already qualified generic kernel/engine probe on the unchanged default branch.
# Hosted WSL and Linux Docker capability probe

This manually dispatched diagnostic measures a fresh hosted Windows VM. It verifies one owned WSL2 distribution, a pinned Linux Docker engine and tiny network-isolated container, actual free physical RAM bracketed by same-engine readiness checks, and cleanup of the owned distribution. The diagnostic requires at least 6144 MiB free RAM; failed or unknown outcomes remain failures.

The source and diagnostic artifacts are public. The workflow uses repository contents read permission and requires its exact repository, actor, image, ref and nonce. The probe receives no application credentials or application source. It uses a digest-verified official Alpine root filesystem, signed Alpine docker-engine and docker-cli packages pinned to version29.9.3-r1 (transitive dependencies are resolved from the signed stable repository), and a digest-pinned BusyBox image. Linux children receive a minimal environment. Docker uses only its local Unix socket; the tiny container has no network.

The current standard public Windows offering is documented as16GB RAM. This repository records actual measurements and does not infer runtime capacity from that specification. A successful probe grants no downstream project or database acceptance. No scheduling, registration, security-policy change or global WSL shutdown is performed.

References: https://docs.github.com/en/actions/reference/runners/github-hosted-runners and https://dl-cdn.alpinelinux.org/alpine/

Raw native streams remain outside published outputs. Only individually bounded normalized UTF-8 copies and structured outcomes are published; oversize or publication errors fail the probe.
