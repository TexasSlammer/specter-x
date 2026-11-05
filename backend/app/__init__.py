"""SPECTER X backend application package.

Layout (CONTRACTS.md is the single source of truth):
    attack_graph/    permission graph: build + deny-first reachability evaluation
    risk_engine/     behavioral detectors D1–D6 + deterministic scoring
    normalization/   vendor-native -> canonical event adapters
    investigations/  alert->case correlation
    response/        simulated response actions (never external calls)
    ingestion.py     validate/dedupe/normalize event batches
    bootstrap.py     demo data loading + scenario evaluation
    main.py          FastAPI app + static dashboard
"""
