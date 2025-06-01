import os
import re
import tempfile
from typing import Optional


def extract_sqlmap_summary(file_path: str, summary_path: Optional[str] = None) -> str:
    
    if not os.path.isfile(file_path):
        return f"[!] Log file not found: {file_path}"

    target = summary_path or file_path
    dir_name = os.path.dirname(target) or "."
    base_name = os.path.basename(target)
    fd, tmp_path = tempfile.mkstemp(prefix=base_name, dir=dir_name, text=True)
    os.close(fd)

    # Regular expressions used throughout -------------------------------------------------
    re_entries = re.compile(r"^\[\d+\s+entries\]", re.I)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as src, \
                open(tmp_path, "w", encoding="utf-8") as dst:

            inside_users = False        
            capture_header = False      
            plus_count = 0               

            for raw in src:
                line = raw.rstrip("\n")
                lower = line.lower().strip()

                # -------- deal with full users dump -------------------------------------
                if inside_users:
                    if lower.startswith("table:") and "users" not in lower:
                        inside_users = False  # finished users block – fall through
                    else:
                        dst.write(raw)
                        continue

                if lower.startswith("table: users"):
                    inside_users = True
                    dst.write(raw)
                    continue

                if capture_header:
                    if line.startswith("+"):
                        plus_count += 1
                        dst.write(raw)
                        if plus_count == 2:
                            capture_header = False
                            plus_count = 0
                        continue
                    elif line.startswith("|"):
                        dst.write(raw)
                        continue
                    else:
                        capture_header = False
                        plus_count = 0
                if re_entries.match(line):
                    capture_header = True
                    plus_count = 0
                    dst.write(raw)  # the "[n entries]" line itself
                    continue

                if "payload" in lower or lower.startswith("database:") or "available databases" in lower \
                        or lower.startswith("table:") or "fetching columns for table" in lower:
                    dst.write(raw)
                    continue

        os.replace(tmp_path, target)
    except Exception as exc:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return f"[!] Error during summary extraction: {exc}"

    return f"[+] Summary written to: {os.path.abspath(target)}"


# if __name__ == "__main__":
#     import sys

#     src = sys.argv[1]
#     dst = sys.argv[2] if len(sys.argv) > 2 else None
#     print(extract_sqlmap_summary(src, dst))
