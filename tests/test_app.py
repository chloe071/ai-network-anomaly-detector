import io
import os
import sys
import tempfile

os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app import app, db

FLOWS = [
    {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 9999, "dst_port": 80, "length": 520.5, "timestamp": 1765749000.0},
    {"src_ip": "192.168.1.11", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 443, "length": 95.0, "timestamp": 1765749001.0},
]


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
    with app.test_client() as c:
        yield c


def test_api_detect_scores_flows(client):
    rv = client.post("/api/detect", json={"flows": FLOWS})
    assert rv.status_code == 200
    assert rv.get_json()["total_flows"] == 2


def test_api_rejects_missing_fields(client):
    rv = client.post("/api/detect", json={"flows": [{"src_ip": "1.2.3.4"}]})
    assert rv.status_code == 400


def test_api_rejects_non_numeric_values(client):
    bad = dict(FLOWS[0], length="huge")
    assert client.post("/api/detect", json={"flows": [bad]}).status_code == 400


def test_api_rejects_empty_body(client):
    assert client.post("/api/detect", data="nope").status_code == 400


def test_csv_upload_works(client):
    csv = "src_ip,dst_ip,src_port,dst_port,length,timestamp\n" + "\n".join(
        f"{f['src_ip']},{f['dst_ip']},{f['src_port']},{f['dst_port']},{f['length']},{f['timestamp']}" for f in FLOWS
    )
    rv = client.post("/upload_csv", data={"file": (io.BytesIO(csv.encode()), "flows.csv")},
                     content_type="multipart/form-data")
    assert rv.status_code == 200
    assert rv.get_json()["total_rows"] == 2


def test_csv_upload_requires_file(client):
    assert client.post("/upload_csv", data={}).status_code == 400
