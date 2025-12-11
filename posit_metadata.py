import os
import json
import re
import tarfile
import pandas as pd
from collections import defaultdict
from dotenv import load_dotenv
import re
from collections import defaultdict

load_dotenv()  # reads .env from current directory

# Set paths
# bundle_path = "realistic_mock_posit_bundle.tar.gz"
extract_path = os.getenv("EXTRACTED_BUNDLE")
manifest_filename= os.getenv("MANIFEST_FILENAME")
rmd_filename=os.getenv("RMD_FILENAME")
csv_filename=os.getenv("CSV_FILENAME")
extracted_bundle_foldername=os.getenv("EXTRACTED_BUNDLE_FOLDERNAME")

os.makedirs(extract_path, exist_ok=True)

# Extract the bundle
# with tarfile.open(bundle_path, "r:gz") as tar:
#     tar.extractall(path=extract_path)

# Helper: Read manifest
def parse_manifest(manifest_path):
    with open(manifest_path, "r", errors="replace") as f:
        return json.load(f)

# Helper: Parse .Rmd file

def parse_rmd(rmd_path, page_heading_level=2):
    """
    Parse an R Markdown (.Rmd) file and extract metadata about:
      - YAML header (title, author, date, output)
      - DB connections
      - file inputs (read_csv, read.csv, read_excel, etc.)
      - tables/views (tbl, sql, dbGetQuery)
      - joins, mutations, summaries, groupings
      - sections/pages and visuals per section

    page_heading_level:
        which heading level to treat as a "page".
        For example:
          #   -> level 1
          ##  -> level 2
          ### -> level 3
        Default: 2 (## headings).
    """
    metadata = defaultdict(list)

    with open(rmd_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # --------- 1. Parse YAML header ---------
    yaml = {}
    if lines and lines[0].strip() == "---":
        yaml_lines = []
        # find closing '---'
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                # YAML is between line 1 and i-1
                yaml_lines = lines[1:i]
                # remaining content starts after this
                body_lines = lines[i+1:]
                break
        else:
            # no closing --- found; treat entire file as body
            body_lines = lines
    else:
        body_lines = lines

    # very simple YAML parser (good enough for standard Rmd headers)
    for yline in yaml_lines:
        ystrip = yline.strip()
        if not ystrip or ystrip.startswith("#"):
            continue
        if ":" in ystrip:
            key, value = ystrip.split(":", 1)
            yaml[key.strip()] = value.strip().strip('"').strip("'")

    metadata["yaml"] = yaml

    # --------- 2. Walk through body, track sections & visuals ---------
    page_count = 0
    visuals_per_page = []
    current_page_visuals = 0

    # Track whether we're inside an R chunk (```{r ...} ... ```)
    in_r_chunk = False
    current_chunk_lines = []

    # Regex helpers
    heading_pattern = re.compile(r"^(#+)\s+(.*)")
    dbconnect_pattern = re.compile(r"dbConnect\((.*?)\)")
    file_read_patterns = [
        re.compile(r"read[_\.]csv\((.*?)\)"),
        re.compile(r"read[_\.]excel\((.*?)\)"),
        re.compile(r"readr::read_csv\((.*?)\)"),
    ]
    visual_markers = ["ggplot(", "plot_ly(", "renderPlot", "renderTable", "geom_", "qplot("]

    for raw_line in body_lines:
        stripped = raw_line.strip()

        # --- Detect chunk start/end ---
        if stripped.startswith("```{r"):
            in_r_chunk = True
            current_chunk_lines = [stripped]
            continue
        elif stripped == "```" and in_r_chunk:
            # End of R chunk – process collected chunk
            chunk_code = "\n".join(current_chunk_lines)
            _process_r_chunk(chunk_code, metadata, dbconnect_pattern, file_read_patterns)
            in_r_chunk = False
            current_chunk_lines = []
            continue

        if in_r_chunk:
            current_chunk_lines.append(stripped)

        # --- Headings / "pages" ---
        m = heading_pattern.match(stripped)
        if m:
            hashes, title = m.groups()
            level = len(hashes)
            # Record any ongoing page visual count
            if level == page_heading_level:
                if page_count > 0:
                    visuals_per_page.append(current_page_visuals)
                page_count += 1
                current_page_visuals = 0
            # Store all headings if you want later:
            metadata["headings"].append({"level": level, "title": title})
            continue

        # --- Visuals (also count visuals outside chunks, e.g. inline) ---
        if any(marker in stripped for marker in visual_markers):
            current_page_visuals += 1
            metadata["visuals"].append(stripped)

        # --- Line-level patterns (joins, mutate, etc.) ---
        if any(j in stripped for j in ["left_join", "right_join", "inner_join", "full_join"]):
            metadata["joins"].append(stripped)

        if "mutate(" in stripped:
            metadata["calculated_columns"].append(stripped)

        if "summarise(" in stripped or "summarize(" in stripped:
            metadata["measures"].append(stripped)

        if "group_by(" in stripped:
            metadata["hierarchies"].append(stripped)

        if "tbl(" in stripped or "sql(" in stripped or "dbGetQuery(" in stripped:
            metadata["tables_views"].append(stripped)

    # End of file: close last page visual count
    if page_count > 0:
        visuals_per_page.append(current_page_visuals)

    metadata["page_count"] = page_count
    metadata["visuals_per_page"] = visuals_per_page

    return dict(metadata)

def _process_r_chunk(chunk_code, metadata, dbconnect_pattern, file_read_patterns):
    """
    Helper to process R chunk code and update metadata dict in-place.
    """
    lines = chunk_code.splitlines()

    for line in lines:
        stripped = line.strip()

       # DB connections (e.g. con <- dbConnect(RPostgres::Postgres(), ...))
        if "dbConnect(" in stripped:
            metadata["connection_type"].append("dbConnect")
            conn_match = dbconnect_pattern.search(stripped)
            if conn_match:
                metadata["connection_raw"].append(conn_match.group(1))

        # File reads
        for pat in file_read_patterns:
            if pat.search(stripped):
                metadata["file_inputs"].append(stripped)
                
# Helper: Analyze CSV for column info
def analyze_csv(csv_path):
    df = pd.read_csv(csv_path)
    col_meta = []

    for col in df.columns:
        dtype = str(df[col].dtype)
        max_len = df[col].astype(str).str.len().max()
        col_meta.append({
            "column_name": col,
            "data_type": dtype,
            "max_length": int(max_len) if not pd.isna(max_len) else None
        })
    return col_meta

# Paths
manifest_path = os.path.join(extract_path, "mock_realistic_bundle",manifest_filename)
rmd_path = os.path.join(extract_path, "mock_realistic_bundle",rmd_filename)
csv_path = os.path.join(extract_path, "mock_realistic_bundle", "data", csv_filename)

# Parse all
manifest_data = parse_manifest(manifest_path)
rmd_metadata = parse_rmd(rmd_path)
csv_columns = analyze_csv(csv_path)


# Combine result
final_metadata = {
    "manifest": manifest_data,
    "report_rmd_metadata": rmd_metadata,
    "csv_column_metadata": csv_columns
}

def extract_file_list_from_manifest(manifest_data):
    files = manifest_data.get("files", {})
    print(list(files.keys()))

extract_file_list_from_manifest(manifest_data)
# Save to JSON
output_json_path = "final_metadata_output.json"
with open(output_json_path, "w", encoding="utf-8") as f:
    json.dump(final_metadata, f, indent=2)
    print("CREATED : final_metadata_output.json ")

output_json_path