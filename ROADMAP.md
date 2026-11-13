# DeepShield — Project Roadmap

This roadmap describes planned improvements for DeepShield. It is a direction for future development, not a promise of delivery dates. Items are not complete unless they are explicitly marked as completed.

## Project status

- [x] v1.0.0 public release
- [x] Live SOC monitoring and CSV traffic analysis workflows
- [x] Binary and multiclass XGBoost prediction
- [x] Isolation Forest anomaly signal and SHAP explanations
- [x] Contribution guidelines

## Phase 1 — Reliability and validation

- [ ] Compare live flow features with CICFlowMeter output on the same packet captures.
- [ ] Expand automated tests for flow creation, bidirectional aggregation, timeout handling, and flow expiration.
- [ ] Test event persistence and dashboard consistency across provisional and final predictions.
- [ ] Document reproducible test captures and validation steps.

## Phase 2 — Detection quality and generalization

- [ ] Evaluate models on additional held-out capture files and unseen network traffic.
- [ ] Investigate missed attacks and improve recall without causing an unacceptable increase in false positives.
- [ ] Review class imbalance and limited-support attack families.
- [ ] Calibrate and document anomaly thresholds separately from supervised attack predictions.
- [ ] Report precision, recall, F1, ROC-AUC, and false-positive rate for clearly defined evaluation splits.

## Phase 3 — SOC dashboard and event analytics

- [ ] Improve event deduplication and prevent repeated provisional snapshots from inflating totals.
- [ ] Separate flow-level statistics from prediction-event statistics throughout the dashboard.
- [ ] Add useful event filters and clearer alert investigation details.
- [ ] Improve trend views and export consistency.

## Phase 4 — Configuration and deployment security

- [ ] Add network-interface discovery and configurable capture settings.
- [ ] Move operational settings into documented configuration or environment variables.
- [ ] Add authentication and role-based access controls before any multi-user deployment.
- [ ] Review logging, input validation, dependency updates, and deployment hardening.

## Phase 5 — Documentation and community

- [ ] Add reproducible examples for dataset preparation, training, and evaluation.
- [ ] Document model artifact requirements and compatibility.
- [ ] Add focused beginner-friendly issues for tests, documentation, and dashboard improvements.
- [ ] Incorporate community feedback and publish release notes for meaningful changes.

## Guiding principles

1. **Validate before claiming:** live capture functionality does not by itself prove detection accuracy.
2. **Report limitations clearly:** publish evaluation setup, dataset split, and relevant metrics.
3. **Keep safe use central:** capture only traffic on networks and devices you own or are explicitly authorized to monitor.
4. **Keep contributions reproducible:** document setup steps, tests, and expected results.

## How to contribute

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Suggestions and evidence-backed improvements are welcome.

---

*DeepShield is an educational and research project, not a production-certified intrusion detection system.*
