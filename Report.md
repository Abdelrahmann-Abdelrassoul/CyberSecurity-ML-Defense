# ML Project Phase 2 Report

## Team members:
- Ali Ashraf - 202301812
- Abdelrahman Abdelrassoul - 202300056
- Ahmed Mohamady - 202301826
- Youssef Islam Kamel - 202300886

## Problem Statement
In today’s digital world, organizations face an alarming rise in cyber attacks that target sensitive data, disrupt services, and cause significant financial and reputational damage. With attack techniques becoming more sophisticated traditional security systems often fail to detect new and evolving patterns of intrusion in time. Despite heavy investments in cybersecurity infrastructure, companies continue to suffer breaches due to delayed detection, lack of adaptability, and the overwhelming volume of network traffic data that needs to be analyzed.

## Objective
The objective is to build an ML model that classifies 6 types of network traffic for cybersecurity purposes. An effective classifier can help in identifying and mitigating different types of cyberattacks early, preventing large-scale breaches and downtime in network systems.

Traffic classes include:
* DDoS (Distributed Denial of Service)
* DoS (Denial of Service)
* Mirai (Botnet attacks)
* BenignTraffic (Normal traffic)
* Recon (Reconnaissance attacks)
* MITM (Man-In-The-Middle attacks)

Early detection and classification allow security systems to respond and adapt, minimizing the risk of compromised systems.

## Challenges
* Analyzing complex network traffic patterns
* Imbalanced dataset
* The subtlety of certain attack types

---

## Data Exploration and Preprocessing

### Data Summary

* **Total Entries**: 841,654

| Class         | Count   |
| ------------- | ------- |
| DDoS          | 597,507 |
| DoS           | 158,144 |
| Mirai         | 51,273  |
| BenignTraffic | 21,985  |
| Recon         | 6,432   |
| MITM          | 6,313   |

### Insights

* DDoS and DoS dominate the dataset, creating class imbalance.
* Recon and MITM classes are minority classes, vulnerable to being ignored by classifiers.

### Preprocessing Steps
* **Duplicates**: Found and cleaned efficiently.
* **Missing values**: None detected.
* **Feature Scaling**: Used log and RobustScaler when non-tree models where used as (Neural Networks, logistic Regression, and SVM). Not needed for tree models but applied log/sqrt transformations to add enhanced features creating non-linear distribution showing hidden patterns in data.
* **Categorical Encoding**: Target column was label encoded.
* **Feature Engineering**: (see section below).
* **Feature Selection**: During testing different models, new features were added progressively, and some of the initial features were dropped using `SelectKBest`. These changes were validated with Cross-Validation accuracy score, Training accuracy score, and Kaggle testing accuracy score. However, in the end, the model with the highest score was the one that included all the following added features and the initial features except for `src_rate` because it was identical to `overall_rate`, and `dst_rate` as it mostly consisted of zeros.

---

## Feature Engineering

### Initial Features

* `flow_time`: Duration of the traffic flow.
* `header_size`: Size of headers.
* `packet_duration`: Time difference between packets.
* `overall_rate`: Rate of flow (packets/sec).
* `src_rate`: Data transfer rate from the source.
* `dst_rate`: Data transfer rate towards the destination.
* `fin_packets`: Number of packets flagged as finished (FIN).
* `urg_packets`: Number of urgent packets (URG).
* `rst_packets`: Number of reset packets (RST).
* `value_covariance`: Maximum value observed in packet data.
* `max_value`: Maximum value observed in packet data.
* `fin_flags`, `syn_flags`, `rst_flags`, `psh_flags`, `ack_flags`: Hot-encoded presence flags (0/1 per flow).
* Protocols: `protocol_http`, `protocol_https`, `protocol_tcp`, `protocol_udp`, `protocol_icmp`.

### Added Features

#### 1. Basic Ratios

1. `header_per_time`: Detects heavy packet headers in short time — (DDoS bursts).

```python
header_per_time = header_size / (flow_time + 1e-6)
```

2. `packet_per_rate`: Catches traffic with lots of packets at abnormal rates.

```python
packet_per_rate = packet_duration / (overall_rate + 1e-6)
```

3. `header_per_packet`: Detects overly large headers (Recon, MITM).

```python
header_per_packet = header_size / (packet_duration + 1e-6)
```

4. `packet_per_time`: Shows packet spread over flow time.

```python
packet_per_time = packet_duration / (flow_time + 1e-6)
```

5. `rate_per_header`: Extreme rates for small headers = botnet or DoS signals.

```python
rate_per_header = overall_rate / (header_size + 1e-6)
```

6. `max_per_cov`: Helps detect bursty, unstable attack flows.

```python
max_per_cov = max_value / (value_covariance + 1e-6)
```

#### 2. Flag Interactions

7. `total_flags`: Total activity on TCP flags.

```python
total_flags = fin_flags + syn_flags + rst_flags + psh_flags + ack_flags
```

8. `fin_ratio`: High in normal ends, low in DoS/DDoS which flood with SYN or RST.

```python
fin_ratio = fin_flags / (total_flags + 1e-6)
```

9. `flags_ratio`: Detects SYN flood patterns.

```python
flags_ratio = syn_flags / (ack_flags + 1e-6)
```

10. `is_syn_ack`: Marks valid handshake flows.

```python
is_syn_ack = (syn_flags > 0) & (ack_flags > 0)
```

11. `syn_fin_combo`: SYN + FIN together is abnormal.

```python
syn_fin_combo = syn_flags * fin_flags
```

12. `ack_psh_combo`: Indicates payload push activity.

```python
ack_psh_combo = ack_flags * psh_flags
```

13. `tcp_fin_ack`: Valid TCP flows closing properly.

```python
tcp_fin_ack = protocol_tcp * fin_flags * ack_flags
```

#### 3. Protocol Interactions

14. `protocol_count`: High counts can indicate attacks using multiple vectors.

```python
protocol_count = protocol_http + protocol_https + protocol_tcp + protocol_udp + protocol_icmp
```

15. `tcp_udp_ratio`: Detects shifts in protocol usage.

```python
tcp_udp_ratio = (protocol_tcp + 1e-6) / (protocol_udp + 1e-6)
```

16. `http_https_ratio`: Tracks balance between normal web traffic and encrypted flows.

```python
http_https_ratio = (protocol_http + 1e-6) / (protocol_https + 1e-6)
```

#### 4. Feature Interactions

17. `flow_rate_interaction`: Amplifies long flows with high rate.

```python
flow_rate_interaction = flow_time * overall_rate
```

18. `header_max_interaction`: Heavy headers + high burst values.

```python
header_max_interaction = header_size * max_value
```

19. `flow_max_interact`: Long flows with burst peaks.

```python
flow_max_interact = flow_time * max_value
```

20. `header_cov_interact`: Variability within headers.

```python
header_cov_interact = header_size * value_covariance
```

21. `packet_time_interact`: Packet spread over time.

```python
packet_time_interact = packet_duration * flow_time
```

22. `rate_sq`: Squares rate to highlight extreme cases.

```python
rate_sq = overall_rate ** 2
```

#### 5. Log/Sqrt Transforms

23. `log_flow_time` and `sqrt_flow_time`: Stabilize flow_time variance.

```python
log_flow_time = np.log1p(flow_time)
sqrt_flow_time = np.sqrt(flow_time)
```

24. `log_header_size` and `sqrt_header_size`: Stabilize header_size variance.

```python
log_header_size = np.log1p(header_size)
sqrt_header_size = np.sqrt(header_size)
```

25. `log_packet_duration` and `sqrt_packet_duration`: Stabilize packet_duration variance.

```python
log_packet_duration = np.log1p(packet_duration)
sqrt_packet_duration = np.sqrt(packet_duration)
```

26. `log_overall_rate` and `sqrt_overall_rate`: Stabilize overall_rate variance.

```python
log_overall_rate = np.log1p(overall_rate)
sqrt_overall_rate = np.sqrt(overall_rate)
```

27. `log_max_value` and `sqrt_max_value`: Stabilize max_value variance.

```python
log_max_value = np.log1p(max_value)
sqrt_max_value = np.sqrt(max_value)
```

28. `log_value_covariance` and `sqrt_value_covariance`: Stabilize value_covariance variance.

```python
log_value_covariance = np.log1p(value_covariance)
sqrt_value_covariance = np.sqrt(value_covariance)
```

#### 6. Binned Indicators

29. `is_long_flow`: Long-lived attack flows.

```python
is_long_flow = flow_time > flow_time.median()
```

30. `is_high_rate`: High-speed flows.

```python
is_high_rate = overall_rate > overall_rate.quantile(0.75)
```

31. `is_small_packet`: Small packet floods.

```python
is_small_packet = header_size < header_size.quantile(0.25)
```

#### 7. Flag Ratios

32. `syn_to_ack_ratio`: High ratio → SYN flood.

```python
syn_to_ack_ratio = syn_flags / (ack_flags + 1)
```

33. `fin_to_rst_ratio`: Detects normal terminations.

```python
fin_to_rst_ratio = fin_flags / (rst_flags + 1)
```

34. `ack_psh_to_total_ratio`: Heavy ACK + payload pushing.

```python
ack_psh_to_total_ratio = (ack_flags + psh_flags) / (total_flags + 1)
```

#### 8. Phase 2 (Attack Patterns)

35. `rst_ratio`: Detects RST floods.

```python
rst_ratio = rst_flags / (total_flags + 1e-6)
```

36. `icmp_ratio`: Detects ICMP-based attacks.

```python
icmp_ratio = protocol_icmp / (protocol_count + 1e-6)
```

37. `is_syn_no_ack`: Incomplete handshakes.

```python
is_syn_no_ack = (syn_flags > 0) & (ack_flags == 0)
```


---

## Models Tried

### 1. KNN Classifier

* Too slow and inefficient on big data

### 2. Decision Tree

* Overfits small datasets

### 3. Random Forest

#### Baseline Random Forest

* Used without class balancing

#### Then Tried:

* With `class_weight='balanced'`: slight improvement
* With SMOTE: no significant benefit with trees

#### Best Params (Kaggle score: 0.913085)

```python
rf_params = {
    'n_estimators': 200,
    'max_depth': 15,
    'min_samples_split': 4,
    'random_state': 42
}
```

### 4. SVM (rbf)

* Took to long in runtime
* Not scalable on multi-class large datasets

### 6. Neural Network

* Accuracy: ~0.87
* Struggled with small classes like Recon & MITM

### 7. XGBoost (Main Model)
#### Best model Used:
| Parameter          | Value                   |
| ------------------ | ----------------------- |
| `max_depth`        | 10                      |
| `learning_rate`    | 0.025                   |
| `subsample`        | 0.7                     |
| `colsample_bytree` | 0.7                     |
| `objective`        | multi:softprob          |
| `num_class`        | `n_classes`             |
| `random_state`     | 42                      |
| `reg_alpha`        | 2                       |
| `reg_lambda`       | 2                       |
| `tree_method`      | hist                    |
| `eval_metric`      | ['mlogloss', 'merror']  |

Training Setup:
| Parameter               | Value                    |
| ----------------------- | ------------------------ |
| `num_boost_round`       | 800                      |
| `early_stopping_rounds` | 20                       |
| `n_splits` (CV folds)   | 5                        |
| `evals`                 | Train + Validation folds |
| `verbose_eval`          | 10                       |


#### Training Method

* **StratifiedKFold (5 splits)**
* Early stopping on `mlogloss` and `merror` with `early_stopping_rounds=20`
* Verbose = 10

 * Cross-Validation Accuracy: 0.0.9098
 * Full Train Set Accuracy: 0.915482
 * Kaggle Accuracy: 0.915482

#### Classification Report

| Class         | Precision | Recall | F1-Score | Support  |
|---------------|-----------|--------|----------|----------|
| BenignTraffic | 0.91      | 0.99   | 0.95     | 21,985   |
| DDoS          | 0.92      | 0.98   | 0.95     | 597,507  |
| DoS           | 0.89      | 0.68   | 0.77     | 158,144  |
| MITM          | 0.97      | 0.86   | 0.91     | 6,313    |
| Mirai         | 1.00      | 1.00   | 1.00     | 51,273   |
| Recon         | 0.94      | 0.85   | 0.89     | 6,432    |

#### Overall Metrics

- **Accuracy**: 0.92 (841,654 samples)
- **Macro Average**:
  - Precision: 0.94
  - Recall: 0.89
  - F1-Score: 0.91
- **Weighted Average**:
  - Precision: 0.92
  - Recall: 0.92
  - F1-Score: 0.92

#### Confusion Matrix & Visuals

* XGBoost shows best separation especially for **DDoS**, **DoS**, and **Mirai**.

* **Recon** and **MITM** improve significantly after adding flag-based and attack pattern features.
![alt text](download.png)
![alt text](download-1.png)
![alt text](download-2.png)

### 8.Ensembling (Stacking)

* Models: Neural Networks, XGBoost,Kight GBM
#### Parameters:
##### Neural Networks
| Parameter           | Value                                |
| ------------------- | ------------------------------------ |
| Input Shape         | `(n_features,)`                      |
| Dense Layers        | 128 → 64 → 32 → `n_classes`          |
| Activations         | LeakyReLU (α=0.01), Softmax (output) |
| Batch Normalization | Yes                                  |
| Dropout Rates       | 0.3 → 0.25 → 0.2                     |
| Optimizer           | Adam (learning_rate=0.001)           |
| Loss                | sparse_categorical_crossentropy      |
| Metrics             | accuracy                             |

#### XGBoost
| Parameter          | Value           |
| ------------------ | --------------- |
| `n_estimators`     | 200             |
| `max_depth`        | 6               |
| `learning_rate`    | 0.1             |
| `subsample`        | 0.8             |
| `colsample_bytree` | 0.8             |
| `objective`        | multi:softprob  |
| `num_class`        | `n_classes`     |
| `eval_metric`      | mlogloss        |
| `random_state`     | 42              |

#### LightGBM
| Parameter       | Value      |
| --------------- | ---------- |
| `n_estimators`  | 200        |
| `max_depth`     | 8          |
| `learning_rate` | 0.1        |
| `num_leaves`    | 31         |
| `objective`     | multiclass |
| `class_weight`  | balanced   |
| `random_state`  | 42         |

* Meta model: Logistic Regression
* Train Accuracy: 0.8764 | F1 Score: 0.8765 | Precision: 0.8773
* Kaggle score: 0.850718
---

## Conclusion

### Key Findings

* **Feature Engineering affects results more than  Hyperparameter tuning** for this dataset.

* Flags-based features improved results.

* Log/sqrt transformations reduced overfitting and improved generalization.


### Real-World Impact

* Model can automate detection of different attacks in near real-time.

* Highlights unusual patterns which is useful in security appliances.

### Limitations

* Minority classes require careful handling — boosting helps but data balancing could improve further.

* The model depends on engineered features as the initial features are too weak for the model to classify.

### Ethical Considerations

* Detection models should be used ethically, ensuring privacy and avoiding false positives that could harm benign users.