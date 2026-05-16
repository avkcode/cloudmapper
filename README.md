# cloudmapper

`cloudmapper` is a standalone Rust CLI for turning AWS and Kubernetes reality
into an agent-readable `infra/` bundle and SQLite `map.db`. It stores resources,
relationships, scan errors, Terraform mappings, compare findings, cost overlays,
and a local Cytoscape/D3 UI for topology, risk, drift, and FinOps inspection.

[GitHub repository](https://github.com/ingresslabs/cloudmapper) ·
[Latest release](https://github.com/ingresslabs/cloudmapper/releases/latest)

## Install

Linux:

```bash
curl -L https://github.com/ingresslabs/cloudmapper/releases/latest/download/cloudmapper-linux.tar.gz | tar -xz
sudo install -m 0755 cloudmapper /usr/local/bin/cloudmapper
```

macOS:

```bash
curl -L https://github.com/ingresslabs/cloudmapper/releases/latest/download/cloudmapper-macos.tar.gz | tar -xz
sudo install -m 0755 cloudmapper /usr/local/bin/cloudmapper
```

## Article

[Read the project walkthrough on Medium](https://medium.com/p/d1178790626d)

## Quick Start

Run the AWS demo without credentials:

```bash
make demo
make demo-ui
```

Run the Kubernetes demo without a cluster:

```bash
make demo-k8s
make demo-k8s-ui
```

Open `http://127.0.0.1:8765`.

## Real Scans

AWS:

```bash
cloudmapper scan aws --profile default --regions all --out infra
cloudmapper terraform import --state terraform.tfstate --db infra/map.db
cloudmapper compare --db infra/map.db --out findings.json
cloudmapper cost actual --db infra/map.db --profile default --tag Environment --tag Application
cloudmapper ui --db infra/map.db --bind 127.0.0.1:8765
```

Kubernetes:

```bash
cloudmapper scan k8s --context kind-prod --namespace all --out infra-k8s
cloudmapper ui --db infra-k8s/map.db --bind 127.0.0.1:8765
```

## Cost And UI

AWS scans automatically write estimated list-price costs from inventory
metadata. `cloudmapper cost actual` imports billed Cost Explorer cost grouped by
service and allocation tags. In the UI, use the cost toggle for graph overlays
and the D3 Cost Analytics view for estimated, actual, and delta analysis by
hour, day, month, service, environment, application, owner, or region.

## Development

```bash
make build
make test
make check
make clippy
```

Release builds are created from annotated `v*` tags.
