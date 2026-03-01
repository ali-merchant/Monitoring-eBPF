# Monitoring-eBPF

**What Notebook contains**
- Feature extraction per PID 
- Baseline scores: count high and medium events, output (normal/anomaly)
- Fuzzy scoring: continuous 0–100 risk score (high*8, medium*1, bonuses for suspicious ops, browser adjustment)
- To make RL learn critical events, oversampled some risks to balance training data
- RL model: simple q-learning (4 actions: ignore/log/alert/block)
- Final results saved to csv 
