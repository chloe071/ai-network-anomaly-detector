from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask import request
import pandas as pd
import numpy as np
import threading
import time
import os
import joblib

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
iso_model = joblib.load(os.path.join(BASE_DIR, "isolation_forest.joblib"))
feature_cols = joblib.load(os.path.join(BASE_DIR, "feature_cols.joblib"))

REQUIRED_COLS = {'src_ip', 'dst_ip', 'src_port', 'dst_port', 'length', 'timestamp'}
MAX_FLOWS = 10_000


def build_features(df):
    """Map flow fields onto the model's NSL-KDD feature columns.

    Note: the model was trained on NSL-KDD numeric features, and live flows
    don't have all of those fields, so packet length and ports are mapped
    onto feature slots 0, 4, 5, 22, 23. See README "Limitations".
    """
    return pd.DataFrame({
        0: pd.to_numeric(df['length']),
        4: pd.to_numeric(df['src_port']),
        5: pd.to_numeric(df['dst_port']),
        22: pd.to_numeric(df['length']),
        23: pd.to_numeric(df['dst_port']),
    })[feature_cols].astype(float)


def score_flows(df):
    """Add anomaly_score and is_anomaly columns using the Isolation Forest."""
    X_live = build_features(df)
    df['is_anomaly'] = (iso_model.predict(X_live) == -1)
    df['anomaly_score'] = -iso_model.decision_function(X_live)  # higher = more anomalous
    return df

# ----------------------
# Flask + DB setup
# ----------------------
app = Flask(__name__)

# SQLite DB in project root (anomaly.db)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///anomaly.db')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB upload limit
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------------
# Database models
# ----------------------
class Capture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    started_at = db.Column(db.Float, nullable=False)
    packet_count = db.Column(db.Integer, nullable=False)

class AnomalyEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    capture_id = db.Column(db.Integer, db.ForeignKey('capture.id'), nullable=False)
    src_ip = db.Column(db.String(64), nullable=False)
    dst_ip = db.Column(db.String(64), nullable=False)
    src_port = db.Column(db.Integer, nullable=False)
    dst_port = db.Column(db.Integer, nullable=False)
    length = db.Column(db.Float, nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(16), nullable=False)   # new
    tag = db.Column(db.String(64), nullable=False)        # new

    capture = db.relationship('Capture', backref=db.backref('anomalies', lazy=True))

# ----------------------
# In‑memory capture state
# ----------------------
packets = []
capture_active = False

def simulate_capture():
    """
    Simulate ~10 seconds of mixed normal/anomalous packets
    and persist a Capture row when done.
    """
    global packets, capture_active
    packets = []
    start_ts = time.time()
    capture_active = True

    for _ in range(100):
        if not capture_active:
            break
        time.sleep(0.1)  # ~10 seconds total

        # 10% anomalies: bigger length, weird ports
        if np.random.random() < 0.1:
            pkt_size = np.random.normal(500, 100)
            src_port = np.random.choice([80, 443, 8080, 9999])
        else:
            pkt_size = np.random.normal(100, 20)
            src_port = np.random.choice([80, 443])

        packets.append({
            'src_ip': f'192.168.1.{np.random.randint(1, 255)}',
            'dst_ip': '10.0.0.1',
            'src_port': int(src_port),
            'dst_port': int(np.random.choice([80, 443])),
            'length': float(max(0, pkt_size)),
            'timestamp': float(time.time())
        })

    capture_active = False

    # Save capture metadata in DB
    with app.app_context():
        cap = Capture(started_at=start_ts, packet_count=len(packets))
        db.session.add(cap)
        db.session.commit()

#Severity and tag anomalies
def classify_severity(row):
    weird_port = row['src_port'] not in (80, 443)
    big_packet = row['length'] > 400
    high_score = row['anomaly_score'] > 0.5

    if weird_port and big_packet and high_score:
        return "high"
    if big_packet or high_score:
        return "medium"
    return "low"

def classify_tag(row):
    if row['length'] > 400:
        return "Unusual packet size"
    if row['src_port'] not in (80, 443):
        return "Suspicious outbound port"
    return "General anomaly"

# ----------------------
# Routes
# ---------------------- 

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture')
def start_capture():
    """
    Start simulated capture in a background thread.
    """
    t = threading.Thread(target=simulate_capture, daemon=True)
    t.start()
    return jsonify({'status': 'Capturing traffic for ~10 seconds...'})

@app.route('/detect')
def detect():
    """
    Use Isolation Forest (trained on NSL-KDD) to score current packets,
    return top anomalies as JSON, and log them to SQLite with severity + tag.
    """
    if len(packets) < 10:
        return jsonify({'error': f'Capture first! Only {len(packets)} packets'})

    # Current capture as DataFrame
    df = pd.DataFrame(packets)

    df = score_flows(df)

    # ---- Save anomalies to SQLite with severity + tag ----
    with app.app_context():
        cap = Capture.query.order_by(Capture.id.desc()).first()
        if cap:
            for row in df[df['is_anomaly']].to_dict('records'):
                sev = classify_severity(row)   # must return a string
                tag = classify_tag(row)        # must return a string

                event = AnomalyEvent(
                    capture_id=cap.id,
                    src_ip=row['src_ip'],
                    dst_ip=row['dst_ip'],
                    src_port=row['src_port'],
                    dst_port=row['dst_port'],
                    length=row['length'],
                    anomaly_score=row['anomaly_score'],
                    timestamp=row['timestamp'],
                    severity=sev,
                    tag=tag,
                )
                db.session.add(event)
            db.session.commit()

    # ---- JSON response for the frontend ----
    results = df[df['is_anomaly']].head(5).to_dict('records')
    return jsonify({
        'anomalies': results,
        'total_anomalies': int(df['is_anomaly'].sum()),
        'total_packets': int(len(df))
    })

@app.route('/dashboard')
def dashboard():
    """
    Return stats + time‑series data for Chart.js.
    """
    if len(packets) < 10:
        return jsonify({'error': f'Capture first! Only {len(packets)} packets'})

    df = pd.DataFrame(packets)
    features = ['length', 'src_port', 'dst_port']

    z_scores = np.abs((df[features] - df[features].mean()) / df[features].std())
    df['anomaly_score'] = z_scores.max(axis=1)

    stats = {
        'total_packets': int(len(df)),
        'anomalies': int((df['anomaly_score'] > 3).sum()),
        'top_src_ips': df['src_ip'].value_counts().head(5).to_dict()
    }

    return jsonify({
        'stats': stats,
        'lengths': df['length'].tolist(),
        'scores': df['anomaly_score'].tolist(),
        'timestamps': df['timestamp'].tolist()
    })

#CSV upload + detection
@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    """
    Accept a CSV of flows, run the same Isolation Forest detector,
    and return anomalies as JSON.
    Expected columns: src_ip,dst_ip,src_port,dst_port,length,timestamp
    """
    file = request.files.get('file')
    if file is None or file.filename == '':
        return jsonify({'error': 'No CSV file uploaded'}), 400

    try:
        df = pd.read_csv(file)
    except Exception:
        return jsonify({'error': 'Failed to read CSV file'}), 400

    if not REQUIRED_COLS.issubset(df.columns):
        return jsonify({'error': f'CSV missing required columns: {sorted(REQUIRED_COLS)}'}), 400
    if len(df) > MAX_FLOWS:
        return jsonify({'error': f'CSV has more than {MAX_FLOWS} rows'}), 400

    try:
        df = score_flows(df)
    except (ValueError, TypeError):
        return jsonify({'error': 'length, src_port, and dst_port must be numeric'}), 400

    anomalies = df[df['is_anomaly']].to_dict('records')
    return jsonify({
        'total_rows': int(len(df)),
        'total_anomalies': int(df['is_anomaly'].sum()),
        'anomalies': anomalies[:50]  # limit payload size
    })

@app.route('/api/detect', methods=['POST'])
def api_detect():
    """
    API endpoint: accept JSON list of flows and return anomalies.
    Body format:
    {
      "flows": [
        {"src_ip": "...", "dst_ip": "...", "src_port": 80, "dst_port": 443,
         "length": 123.4, "timestamp": 1765740000.0},
        ...
      ]
    }
    """
    data = request.get_json(silent=True)
    if not data or 'flows' not in data:
        return jsonify({'error': 'JSON body must contain "flows" list'}), 400
    
    flows = data['flows']
    if not isinstance(flows, list) or not flows:
        return jsonify({'error': '"flows" must be a non-empty list'}), 400
    
    if len(flows) > MAX_FLOWS:
        return jsonify({'error': f'At most {MAX_FLOWS} flows per request'}), 400
    if not all(isinstance(f, dict) for f in flows):
        return jsonify({'error': 'Each flow must be a JSON object'}), 400

    df = pd.DataFrame(flows)
    if not REQUIRED_COLS.issubset(df.columns):
        return jsonify({'error': f'Each flow must include: {sorted(REQUIRED_COLS)}'}), 400

    try:
        df = score_flows(df)
    except (ValueError, TypeError):
        return jsonify({'error': 'length, src_port, and dst_port must be numeric'}), 400

    anomalies = df[df['is_anomaly']].to_dict('records')

    return jsonify({
        'total_flows': int(len(df)),
        'total_anomalies': int(df['is_anomaly'].sum()),
        'anomalies': anomalies
    })

# ----------------------
# Main
# ----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
