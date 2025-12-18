AI Network Anomaly Detector

AI-powered network anomaly detection dashboard built with Flask, Tailwind, Chart.js, and an Isolation Forest model trained
on the NSL-KDD intrusion detection dataset. The app simulates network traffic, runs an ML model to flag suspicious flows, 
visualizes anomalies in a SOC-style dashboard, and logs detection to SQLite with severity and tags.

Features
- AI anomaly detection

  - Isolation Forest model trained in Colab on the NSL‑KDD dataset and exported with joblib.

  - Live traffic simulator feeds flows into the model to compute anomaly scores.

  - Same model can score uploaded CSV flow files and JSON flows via an API endpoint.

SOC‑style dashboard

  - Dark, modern UI using Tailwind CSS.

  - Cards for total packets, anomalies, and top source IPs.

  - Chart.js visualizations:

    - Packet length distribution (bar chart).

    - Anomaly scores over time (line chart).
      
  - Recent anomalies table with src/dst IPs, ports, length, score, and timestamp.
Alert severity and tagging

  - Each anomaly is enriched with:

    - Severity: low, medium, high based on port, packet length, and score.

    - Tag: simple labels like “Unusual packet size” or “Suspicious outbound port”.

  - Anomalies are persisted to SQLite via Flask‑SQLAlchemy for future analysis.
Extensible detection pipeline

  - CSV upload: upload a flow CSV and run the same detection pipeline.

  - API‑first: /api/detect endpoint accepts JSON flows and returns anomalies, so other tools or scripts can integrate.

Tech stack
Backend

  - Python, Flask

  - Flask‑SQLAlchemy (SQLite)

  - scikit‑learn (Isolation Forest)

  - joblib (model persistence)

Frontend

  - Tailwind CSS (Play CDN)

  - Chart.js

  - Vanilla JavaScript (fetch API)

Data & ML

  - NSL‑KDD intrusion detection dataset

  - Isolation Forest anomaly detection model trained in Google Colab

Architecture
High‑level flow:

1. Training (Colab)

   - Load NSL‑KDD dataset.

   - Select numeric features and train an Isolation Forest model.

   - Evaluate on a test split and record F1 score.

   - Save isolation_forest.joblib and feature_cols.joblib.

2. App runtime (Flask)

   - Simulate network traffic (private IPs, ports, packet lengths, timestamps).

   - Build feature vectors matching the NSL‑KDD training schema.

   - Run Isolation Forest to compute anomaly scores and labels.

   - Classify severity and tag each anomaly.

   - Log anomalies to SQLite (Capture and AnomalyEvent tables).

   - Expose results via:

     - HTML dashboard.

     - CSV upload route.

     - JSON API endpoint.

Getting started
1. Clone and set up environment
bash
git clone https://github.com/chloe071/ai-network-anomaly-detector.git
cd ai-network-anomaly-detector

python3 -m venv env
source env/bin/activate  # Windows: env\Scripts\activate

pip install -r requirements.txt  # or pip install flask flask-sqlalchemy pandas numpy scikit-learn joblib
Make sure isolation_forest.joblib and feature_cols.joblib (exported from your Colab notebook) are in the project root alongside app.py.

2. Initialize database and run the app
bash
python app.py
By default, the app runs on http://127.0.0.1:5000.

On first run, the SQLite database is created automatically.

How to use
Live simulated traffic
1. Open http://127.0.0.1:5000 in your browser.

2. Click Capture Traffic (10s) to simulate a short burst of traffic.

3. Click Detect Anomalies:

   - The backend builds feature vectors from the captured flows.

   - The Isolation Forest model scores each flow and flags anomalies.

   - Anomalies are saved to SQLite with severity and tag.

4. Click Refresh Dashboard to update stats and charts.
You’ll see:

   - Total packets and anomaly count.

   - Top source IPs.

   - Packet length and anomaly score charts.

   - A table of recent anomalies.

Uploading a CSV of flows
1. Prepare a CSV with columns similar to:

src_ip,dst_ip,src_port,dst_port,length,timestamp
192.168.1.10,10.0.0.1,9999,80,520.5,1765749000.0
192.168.1.11,10.0.0.1,80,443,95.0,1765749001.0

2. In the UI, under Import flows CSV, choose your CSV and click Run Detection on CSV.

3. The results table populates with anomalies from that file.

API mode: /api/detect
Example request body:

{
  "flows": [
    {
      "src_ip": "192.168.1.10",
      "dst_ip": "10.0.0.1",
      "src_port": 9999,
      "dst_port": 80,
      "length": 520.5,
      "timestamp": 1765749000.0
    },
    {
      "src_ip": "192.168.1.11",
      "dst_ip": "10.0.0.1",
      "src_port": 80,
      "dst_port": 443,
      "length": 95.0,
      "timestamp": 1765749001.0
    }
  ]
}

Example curl:

curl -X POST http://127.0.0.1:5000/api/detect \
  -H "Content-Type: application/json" \
  -d @example_flows.json
Response includes total_flows, total_anomalies, and a list of anomalous flows with scores.

Model training (NSL‑KDD)
Training is done in a separate Google Colab notebook:

1. Install dependencies (scikit-learn, pandas, joblib).

2. Load the NSL‑KDD training data.

3. Build numeric feature matrix and binary labels (normal vs attack).

4. Train an Isolation Forest:

   - Example parameters: n_estimators=200, contamination=0.1, random_state=42.

5. Evaluate on a held‑out test set and record F1 score.

6. Save the model artifacts:

joblib.dump(iso, "isolation_forest.joblib")
joblib.dump(feature_cols, "feature_cols.joblib")
7. Download those files and drop them into this project.

Possible extensions
   - Use real PCAP data converted to CSV for more realistic flows.

   - Add a /history page to browse historical anomalies with filters by time range, source IP, and severity.

   - Integrate authentication and role‑based access to make it feel like an internal SOC tool.

   - Swap in other models (e.g., autoencoders) or add ensemble scoring.

Why this project
This project is designed as a portfolio piece to demonstrate:

   - Practical use of AI in cybersecurity (not just theory).

   - Full‑stack skills (Flask backend, modern frontend, data persistence).

   - Ability to train and deploy ML models, integrate with dashboards, and design basic alerting logic.
