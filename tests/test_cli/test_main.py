import subprocess
import os


def test_fsa_no_args():
    process = subprocess.run(["fsa"], text=True, stderr=subprocess.PIPE)
    assert "usage: fsa" in process.stderr, "incorrect stdout for fsa"


def test_fsa_help():
    process = subprocess.run(["fsa", "--help"],
                             text=True,
                             stdout=subprocess.PIPE)
    assert process.returncode == 0
    assert "options:" in process.stdout, "fsa run was supposed to give instructions"


def test_fsa_correct_args(tmp_path):
    test_dir = tmp_path / "test_dir"
    os.mkdir(test_dir)
    process = subprocess.run(["fsa", "-d", test_dir, "-t", "10MiB"],
                             text=True,
                             stdout=subprocess.PIPE)
    assert process.returncode == 0
    assert "FILE SYSTEM ANALYSIS REPORT" in process.stdout, "fsa run was supposed to be successful"

def test_integration():
    pass
