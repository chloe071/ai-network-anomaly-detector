# AI Network Anomaly Detector

![tests](https://github.com/chloe071/ai-network-anomaly-detector/actions/workflows/tests.yml/badge.svg)

An AI-powered network anomaly detection dashboard built with Flask, Tailwind, Chart.js, and an Isolation Forest model trained on the NSL-KDD intrusion detection dataset. The app simulates network traffic, runs the model to flag suspicious flows, visualizes anomalies in a SOC-style dashboard, and logs detections to SQLite with severity and tags.

## Features

### AI anomaly detection
- Isolation Forest model trained in Google Colab on NSL-KDD and exported with joblib
- Live traffic simulator feeds flows into the model to compute anomaly scores
- The same model scores uploaded CSV files and JSON flows sent to an API endpoint

### SOC-style dashboard
- Dark UI built with Tailwind CSS
- Cards for total packets, anomalies, and top source IPs
- Chart.js visualizations: packet length distribution and anomaly scores over time
- Recent anomalies table with source/destination IPs, ports, length, score, and timestamp

### Alert severity and tagging
- **Severity** (low, medium, high) based on port, packet length, and score
- **Tag** such as "Unusual packet size" or "Suspicious outbound port"
- Anomalies saved to SQLite via Flask-SQLAlchemy

### Extensible pipeline
- **CSV upload** runs the same detection pipeline on a file
- **`/api/detect`** accepts JSON flows so other tools and scripts can integrate

## Tech Stack

| Layer | Tools |
|---|---|
| Backend | Python, Flask, Flask-SQLAlchemy (SQLite) |
| ML | scikit-learn (Isolation Forest), joblib, pandas, NumPy |
| Frontend | Tailwind CSS (Play CDN), Chart.js, vanilla JavaScript |
| Data | NSL-KDD intrusion detection dataset |
| Testing | pytest, GitHub Actions |

## Architecture

```text
Training (Colab)                    App runtime (Flask)
────────────────                    ───────────────────
Load NSL-KDD                        Simulate traffic / upload CSV / POST JSON
Select numeric features      ──►    Map flows onto model features
Train Isolation Forest              Score with Isolation Forest
Evaluate (F1) on test split         Classify severity + tag
Export .joblib files                Log anomalies to SQLite
                                    Serve dashboard + JSON API
```

## Getting Started

### 1. Clone and set up

```bash
git clone https://github.com/chloe071/ai-network-anomaly-detector.git
cd ai-network-anomaly-detector
python3 -m venv env
source env/bin/activate      # Windows: env\Scripts\activate
pip install -r requirements.txt
```

The trained model files `isolation_forest.joblib` and `feature_cols.joblib` are included in the repository root.

### 2. Run the app

```bash
python app.py
```

Open http://127.0.0.1:5000. The SQLite database is created automatically on first run.

## How to Use

### Live simulated traffic
1. Click **Capture Traffic (10s)** to simulate a short burst of traffic.
2. Click **Detect Anomalies** to score the flows and save anomalies to SQLite.
3. Click **Refresh Dashboard** to update stats and charts.

### Uploading a CSV
Use a CSV with these columns (see [`example_flows.csv`](example_flows.csv)):

```csv
src_ip,dst_ip,src_port,dst_port,length,timestamp
192.168.1.10,10.0.0.1,9999,80,520.5,1765749000.0
192.168.1.11,10.0.0.1,80,443,95.0,1765749001.0
```

Under **Import flows CSV**, choose the file and click **Run Detection on CSV**. Uploads are limited to 5 MB and 10,000 rows.

### API: `/api/detect`

```bash
curl -X POST http://127.0.0.1:5000/api/detect \
  -H "Content-Type: application/json" \
  -d @example_flows.json
```

Request body format (see [`example_flows.json`](example_flows.json)):

```json
{
  "flows": [
    {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 9999,
     "dst_port": 80, "length": 520.5, "timestamp": 1765749000.0}
  ]
}
```

The response includes `total_flows`, `total_anomalies`, and the anomalous flows with scores. Invalid input (missing fields, non-numeric values, more than 10,000 flows) returns a `400` error.

## Model Training (NSL-KDD)

Training was done in a separate Google Colab notebook:

1. Install scikit-learn, pandas, and joblib.
2. Load the NSL-KDD training data.
3. Build a numeric feature matrix and binary labels (normal vs. attack).
4. Train an Isolation Forest (`n_estimators=200`, `contamination=0.1`, `random_state=42`).
5. Evaluate on a held-out test set and record the F1 score.
6. Export the artifacts:

```python
joblib.dump(iso, "isolation_forest.joblib")
joblib.dump(feature_cols, "feature_cols.joblib")
```

## Running Tests

```bash
pip install pytest
pytest -q
```

Tests cover the JSON API, CSV upload, and input validation. They run automatically on every push.

## Limitations

- **Feature mapping:** the model uses five NSL-KDD feature columns (0, 4, 5, 22, 23). Simulated and uploaded flows don't contain those exact fields, so packet length and ports are mapped onto those slots. Scores show the pipeline working end to end but aren't a validated detector for real traffic.
- **Dashboard chart scores** use a simple z-score on the current capture, separate from the Isolation Forest results.
- **Traffic is simulated**, not captured from a real interface.
- **No authentication** — intended for local use only.

## Possible Extensions

- Use real PCAP data converted to CSV for realistic flows
- Retrain the model on features that match the flow data
- Add a `/history` page with filters by time range, source IP, and severity
- Add authentication and role-based access
- Try other models (e.g., autoencoders) or ensemble scoring

## Fix Log

- Fixed the CSV upload route, which was broken by a typo (`request.file` → `request.files`).
- `python app.py` now actually starts the server.
- Added input validation and size limits to the upload and API routes.
- Added a `requirements.txt`, example input files, and automated tests.

## Why This Project

A portfolio piece demonstrating practical AI in cybersecurity, full-stack skills (Flask backend, modern frontend, data persistence), and the ability to train and deploy ML models with basic alerting logic.
