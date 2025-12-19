# Threat-Intel-HASH-Conversion


A Python script to bulk scan file hashes against the VirusTotal API using an input Excel file. This version is modernized to support **Python 3.13+** and **.xlsx files** by utilizing `openpyxl` instead of the deprecated `xlrd`.

###  Features

* **Bulk Processing:** Reads a column of hashes from an input `.xlsx` file.
* **API Rate Limiting:** Includes a 16-second delay between requests to comply with the VirusTotal Public API (4 requests/minute).
* **Robust Error Handling:** Handles non-existent hashes, API limit hits (204), and empty rows without crashing.
* **Data Export:** Saves MD5, SHA-1, SHA-256, Detection Counts, and Scan Status to a new Excel file.
* **Auto-Save:** Saves progress every 10 rows to prevent data loss.

###  Prerequisites

* Python 3.x
* A VirusTotal Public API Key

###  Installation

Install the required dependencies:

```bash
pip install requests openpyxl

```

###  Configuration

1. Open the script in a text editor.
2. Locate the `API_KEY` variable at the top.
3. Paste your VirusTotal API key inside the quotes:
```python
API_KEY = 'YOUR_ACTUAL_API_KEY_HERE'

```



###  Usage

Run the script passing your input Excel file as an argument:

```bash
python3 VTC.py input_hashes.xlsx

```

**Input Format:**
The input Excel file should have the hashes listed in the **first column (Column A)**.

**Output:**
The script generates a file named `HashConvertedOutput.xlsx` containing the scan results.
