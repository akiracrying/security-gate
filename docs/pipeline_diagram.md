# Pipeline diagram (Mermaid)

Export this to PNG/SVG for the article (e.g. Mermaid Live Editor or `mmdc -i pipeline_diagram.md -o pipeline_diagram.png`).

```mermaid
flowchart LR
  subgraph PR["PR stage"]
    A[Checkout] --> B[Gitleaks]
    B --> C[Semgrep]
    C --> D[Trivy SCA]
    D --> E[Dependency review]
    E --> F[Gate decider]
  end

  subgraph Release["Release / main"]
    G[Checkout] --> H[Gitleaks]
    H --> I[CodeQL]
    I --> J[Trivy FS]
    J --> K[Container scan]
    K --> L[Gate decider]
  end

  F -->|allow/warn| M[Merge OK]
  F -->|block| N[Block]
  L -->|allow/warn| M
  L -->|block| N
```

## Gates placement

| Stage   | Gates |
|---------|--------|
| PR      | Secrets (block), SAST in changed (warn/block), SCA (warn), Dependency review (warn/block) |
| Release | Secrets (block), CodeQL high/critical (block), SCA runtime+fix (block), Container (block) |
