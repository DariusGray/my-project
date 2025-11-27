# test_validator.py
# Simple tests to support a red → green → refactor story.

from validator import validate_filename_pattern, validate_header

def test_valid_filename_pattern():
    ok, msg = validate_filename_pattern("CLINICALDATA_20250401121530.csv")
    assert ok
    assert msg is None

def test_invalid_filename_prefix():
    ok, msg = validate_filename_pattern("WRONG_20250401121530.csv")
    assert not ok

def test_valid_header():
    header = [
        "PatientID","TrialCode","DrugCode","Dosage_mg",
        "StartDate","EndDate","Outcome","SideEffects","Analyst",
    ]
    errors = validate_header(header)
    assert errors == []

def test_invalid_header_size():
    header = ["A", "B", "C"]
    errors = validate_header(header)
    assert len(errors) == 1
