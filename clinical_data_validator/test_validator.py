# test_validator.py
import os
from validator import validate_filename_pattern, validate_header, validate_csv_file

def test_validate_filename_pattern_valid():
    ok, msg = validate_filename_pattern("CLINICALDATA_20250401121530.csv")
    assert ok
    assert msg is None

def test_validate_filename_pattern_invalid_prefix():
    ok, msg = validate_filename_pattern("WRONG_20250401121530.csv")
    assert not ok
    assert "Filename does not start" in msg

def test_validate_header_ok():
    header = [
        "PatientID",
        "TrialCode",
        "DrugCode",
        "Dosage_mg",
        "StartDate",
        "EndDate",
        "Outcome",
        "SideEffects",
        "Analyst",
    ]
    errors = validate_header(header)
    assert errors == []

def test_validate_header_wrong_columns():
    header = ["A", "B", "C"]
    errors = validate_header(header)
    assert len(errors) == 1
