from __future__ import annotations

import json

from recon_copilot.fuzzing.ffuf_parser import parse_ffuf_json

SAMPLE_FFUF_OUTPUT = json.dumps(
    {
        "commandline": "ffuf -w wordlist.txt -u http://10.0.0.5/FUZZ",
        "results": [
            {"input": {"FUZZ": "admin"}, "status": 200, "length": 512, "duration": 12_000_000},
            {"input": {"FUZZ": ".env"}, "status": 403, "length": 20, "duration": 5_000_000},
        ],
    }
)


def test_parses_hits_with_status_size_and_duration():
    hits, warnings = parse_ffuf_json(SAMPLE_FFUF_OUTPUT)
    assert len(hits) == 2
    assert warnings == []
    admin_hit = next(h for h in hits if h.payload == "admin")
    assert admin_hit.status_code == 200
    assert admin_hit.body_size == 512
    assert admin_hit.response_time_ms == 12.0


def test_empty_output_returns_warning():
    hits, warnings = parse_ffuf_json("")
    assert hits == []
    assert len(warnings) == 1
    assert "vide" in warnings[0]


def test_invalid_json_returns_warning():
    hits, warnings = parse_ffuf_json("not json at all")
    assert hits == []
    assert len(warnings) == 1


def test_missing_results_field_returns_warning():
    hits, warnings = parse_ffuf_json(json.dumps({"commandline": "x"}))
    assert hits == []
    assert "results" in warnings[0]


def test_missing_fuzz_key_falls_back_to_url():
    output = json.dumps({"results": [{"url": "http://x/y", "status": 200, "length": 10, "duration": 1_000_000}]})
    hits, warnings = parse_ffuf_json(output)
    assert hits[0].payload == "http://x/y"
