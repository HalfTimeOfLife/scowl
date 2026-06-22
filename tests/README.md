# Tests

## Structure

| File | Module tested | Number of tests |
|---|---|---|
| `test_utils.py` | `analysis/utils.py` | 20 |
| `test_generic.py` | `analysis/generic_analyzer.py` | 8 |
| `test_dispatcher.py` | `analysis/dispatcher.py` | 6 |
| `test_script.py` | `analysis/script_analyzer.py` | 18 |

## Samples

The files in `tests/samples/` are used by `test_script.py` and `test_generic.py` :

| File | Used by |
|---|---|
| `test_ps1.ps1` | `test_script.py` |
| `test_bat.bat` | `test_script.py` |
| `test_cmd.cmd` | `test_script.py` |
| `test_vbs.vbs` | `test_script.py` |
| `test_js.js` | `test_script.py` |
| `test_sh.sh` | `test_script.py` |
| `text_test.txt` | `test_generic.py` |

## Run the tests (from project root)

```bash
pytest
```