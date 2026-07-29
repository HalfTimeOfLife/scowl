# Tests

## Structure

| File | Module tested | Number of tests |
|---|---|---|
| `test_utils.py` | `analysis/utils.py` | 20 |
| `test_generic.py` | `analysis/generic_analyzer.py` | 8 |
| `test_dispatcher.py` | `analysis/dispatcher.py` | 7 |
| `test_script.py` | `analysis/script_analyzer.py` | 18 |
| `test_pdf.py` | `analysis/pdf_analyzer.py` | 19 |

## Samples

The files in `tests/samples/` are used by `test_script.py`, `test_generic.py` and `test_pdf.py` :

| File | Used by |
|---|---|
| `test_ps1.ps1` | `test_script.py` |
| `test_bat.bat` | `test_script.py` |
| `test_cmd.cmd` | `test_script.py` |
| `test_vbs.vbs` | `test_script.py` |
| `test_js.js` | `test_script.py` |
| `test_sh.sh` | `test_script.py` |
| `text_test.txt` | `test_generic.py` |
| `test_pdf_malicious.pdf` | `test_pdf.py` |
| `test_pdf_malformed.pdf` | `test_pdf.py` |
| `test_pdf_clean.pdf` | `test_pdf.py` |

> **Note:** the `test_pdf_*.pdf` files are not valid binary PDFs.


## Run the tests (from project root)

```bash
pytest
```