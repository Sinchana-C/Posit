import os
import json
import re
import pandas as pd
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

# below for posit environment
# load_dotenv(dotenv_path=".env", override=False)

extract_path = os.getenv("EXTRACTED_BUNDLE")
manifest_filename = os.getenv("MANIFEST_FILENAME")
rmd_filename = os.getenv("RMD_FILENAME")
csv_filename = os.getenv("CSV_FILENAME")
extracted_bundle_foldername = os.getenv("EXTRACTED_BUNDLE_FOLDERNAME")

os.makedirs(extract_path, exist_ok=True)

# MANIFEST

def parse_manifest(manifest_path):
    with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)

def extract_files_from_manifest(manifest_data):
    files = set()

    if "files" in manifest_data:
        if isinstance(manifest_data["files"], dict):
            files.update(manifest_data["files"].keys())
        elif isinstance(manifest_data["files"], list):
            for f in manifest_data["files"]:
                if isinstance(f, dict) and "path" in f:
                    files.add(f["path"])

    if "content" in manifest_data and "files" in manifest_data["content"]:
        for f in manifest_data["content"]["files"]:
            if "path" in f:
                files.add(f["path"])

    return sorted(files)

def filter_r_sources(file_paths):
    return [
        f for f in file_paths
        if f.lower().endswith((".rmd", ".qmd", ".r"))
    ]

def has_rmd_chunks(lines):
    return any(line.strip().startswith("```{") for line in lines)

def _parse_chunk_options(header):
    parts = [p.strip() for p in header.split(",")]
    chunk_name = None
    opts = {}

    if parts:
        first = re.sub(r"^\s*r\s*", "", parts[0])
        if first and not re.match(r"^\s*=", first):
            chunk_name = first.strip()

    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            opts[k.strip()] = v.strip().strip('"').strip("'")
        else:
            opts[p.strip()] = True

    return chunk_name, opts

# R CHUNK PARSER
def _process_r_chunk(chunk_code, metadata):
    lines = chunk_code.splitlines()
    header_line = lines[0]

    header_inside = ""
    m = re.match(r"^```{\s*r(.*)}", header_line)
    if m:
        header_inside = m.group(1).strip().strip(",")

    chunk_name, chunk_opts = _parse_chunk_options(header_inside)

    metadata["chunks"].append({
        "name": chunk_name,
        "opts": chunk_opts
    })

    body = "\n".join(lines[1:])
    body = re.sub(r"\n```$", "", body)

    # Libraries
    for pkg in re.findall(r"(?:library|require)\(\s*([A-Za-z0-9_.:]+)\s*\)", body):
        metadata["libraries"].append(pkg)

    # File reads
    for m in re.finditer(r"(read[_\.]csv|readr::read_csv|readxl::read_excel)\((.*?)\)", body, re.DOTALL):
        arg = m.group(2)
        literal = re.search(r'["\']([^"\']+)["\']', arg)
        metadata["file_inputs"].append({
            "call": m.group(1),
            "path": literal.group(1) if literal else None,
            "raw": arg
        })

    # Tables / queries
    for t in re.finditer(r"\b(tbl|sql|dbGetQuery)\((.*?)\)", body, re.DOTALL):
        metadata["tables_views"].append(t.group(0))

    # ---------- CALCULATED / DERIVED COLUMNS ----------
    for m in re.finditer(
        r"\b("
        r"mutate|transmute|across|if_else|ifelse|case_when|"
        r"coalesce|replace_na|rename|"
        r"lag|lead|row_number|rank|dense_rank|"
        r"cumsum|cummean|cummax|cummin|"
        r"as\.numeric|as\.integer|as\.character|as\.Date|"
        r"ymd|mdy|dmy"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["calculated_columns"].append(m.group(0).strip())


    # ---------- FILTERS / ROW OPERATIONS ----------
    for f in re.finditer(
        r"\b("
        r"filter|slice|slice_head|slice_tail|"
        r"distinct|arrange"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata.setdefault("filters", []).append(f.group(0).strip())


    # ---------- AGGREGATIONS / MEASURES ----------
    for s in re.finditer(
        r"\b("
        r"summarise|summarize|count|tally"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["measures"].append(s.group(0).strip())


    # ---------- GROUPING / HIERARCHIES ----------
    for g in re.finditer(
        r"\bgroup_by\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["hierarchies"].append(g.group(0).strip())


    # ---------- JOINS (TIDYVERSE + BASE R) ----------
    for j in re.finditer(
        r"\b("
        r"left_join|right_join|inner_join|full_join|merge"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["joins"].append(j.group(0).strip())

    for g in re.finditer(
        r"""
        ggplot\s*\(
        [\s\S]*?(?=\n\s*\n
            | \n\s*}
            | \n\s*[A-Za-z_][A-Za-z0-9_]*\s*<-
            | \n\s*```
            | \Z
        )
        """,body,re.VERBOSE):
        metadata["visuals"].append({
            "type": "ggplot",
            "snippet": g.group(0).strip(),
        })
    # Visuals

    for g in re.finditer(
        r"""
        ggplot\s*\(
        [\s\S]*?(?=\n\s*\n
            | \n\s*}
            | \n\s*[A-Za-z_][A-Za-z0-9_]*\s*<-
            | \n\s*```
            | \Z
        )
        """,body,re.VERBOSE):
        metadata["visuals"].append({
            "type": "ggplot",
            "snippet": g.group(0).strip(),
            "chunk": chunk_name if chunk_name else "__plain_code__"
        })

#plain code parser / lines
def process_plain_code(lines, metadata):
    body = "\n".join(lines)

    metadata["chunks"].append({
        "name": "__plain_code__",
        "opts": {}
    })

    for pkg in re.findall(r"(?:library|require)\(\s*([A-Za-z0-9_.:]+)\s*\)", body):
        metadata["libraries"].append(pkg)

    for m in re.finditer(r"(read[_\.]csv|readr::read_csv|readxl::read_excel)\((.*?)\)", body, re.DOTALL):
        arg = m.group(2)
        literal = re.search(r'["\']([^"\']+)["\']', arg)
        metadata["file_inputs"].append({
            "call": m.group(1),
            "path": literal.group(1) if literal else None,
            "raw": arg
        })
    
    # ---------- CALCULATED / DERIVED COLUMNS ----------
    for m in re.finditer(
        r"\b("
        r"mutate|transmute|across|if_else|ifelse|case_when|"
        r"coalesce|replace_na|rename|"
        r"lag|lead|row_number|rank|dense_rank|"
        r"cumsum|cummean|cummax|cummin|"
        r"as\.numeric|as\.integer|as\.character|as\.Date|"
        r"ymd|mdy|dmy"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["calculated_columns"].append(m.group(0).strip())

    # ---------- FILTERS / ROW OPERATIONS ----------
    for f in re.finditer(
        r"\b("
        r"filter|slice|slice_head|slice_tail|"
        r"distinct|arrange"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata.setdefault("filters", []).append(f.group(0).strip())


    # ---------- AGGREGATIONS / MEASURES ----------
    for s in re.finditer(
        r"\b("
        r"summarise|summarize|count|tally"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["measures"].append(s.group(0).strip())


    # ---------- GROUPING / HIERARCHIES ----------
    for g in re.finditer(
        r"\bgroup_by\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["hierarchies"].append(g.group(0).strip())


    # ---------- JOINS (TIDYVERSE + BASE R) ----------
    for j in re.finditer(
        r"\b("
        r"left_join|right_join|inner_join|full_join|merge"
        r")\s*\(([^)]*)\)",
        body,
        re.DOTALL
    ):
        metadata["joins"].append(j.group(0).strip())

    for g in re.finditer(
        r"""
        ggplot\s*\(
        [\s\S]*?(?=\n\s*\n
            | \n\s*}
            | \n\s*[A-Za-z_][A-Za-z0-9_]*\s*<-
            | \n\s*```
            | \Z
        )
        """,body,re.VERBOSE):
        metadata["visuals"].append({
            "type": "ggplot",
            "snippet": g.group(0).strip(),
        })

def parse_rmd(rmd_path):
    metadata = defaultdict(list)

    for k in [
        "chunks",
        "libraries",
        "file_inputs",
        "tables_views",
        "joins",
        "calculated_columns",
        "measures",
        "hierarchies",
        "visuals"
    ]:
        metadata[k] = []

    with open(rmd_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    if not has_rmd_chunks(lines):
        process_plain_code(lines, metadata)
        return dict(metadata)

    in_chunk = False
    current_chunk = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```{") and "r" in stripped:
            in_chunk = True
            current_chunk = [stripped]
            continue

        if stripped == "```" and in_chunk:
            current_chunk.append(stripped)
            _process_r_chunk("\n".join(current_chunk), metadata)
            in_chunk = False
            current_chunk = []
            continue

        if in_chunk:
            current_chunk.append(stripped)

    if not metadata["chunks"]:
        process_plain_code(lines, metadata)

    return dict(metadata)

# CSV ANALYSIS

def analyze_csv(csv_path):
    df = pd.read_csv(csv_path)
    return [
        {
            "column_name": c,
            "data_type": str(df[c].dtype),
            "max_length": int(df[c].astype(str).str.len().max())
        }
        for c in df.columns
    ]


manifest_path = os.path.join(
    extract_path,
    extracted_bundle_foldername,
    manifest_filename
)

rmd_path = os.path.join(
    extract_path,
    extracted_bundle_foldername,
    rmd_filename
)

csv_path = os.path.join(
    extract_path,
    extracted_bundle_foldername,
    "data",
    csv_filename
)

manifest_data = parse_manifest(manifest_path)
all_files = extract_files_from_manifest(manifest_data)
r_source_files = filter_r_sources(all_files)

all_rmd_metadata = {}

for rel_path in r_source_files:
    abs_path = os.path.join(
        extract_path,
        extracted_bundle_foldername,
        rel_path
    )
    print(abs_path)

    if not os.path.exists(abs_path):
        continue

    all_rmd_metadata[rel_path] = parse_rmd(abs_path)

# print("---")
# print(all_files)
# print("---")

csv_metadata = analyze_csv(csv_path)

final_metadata = {
    "manifest": manifest_data,
    "report_metadata": all_rmd_metadata,
    "csv_column_metadata": csv_metadata
}

with open("final_metadata_output.json", "w", encoding="utf-8") as f:
    json.dump(final_metadata, f, indent=2)
    print("CREATED: final_metadata_output.json")