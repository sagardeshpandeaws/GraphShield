import zipfile
import os
import sys



def create_zip(
    files,
    output
):


    with zipfile.ZipFile(
        output,
        "w"
    ) as z:


        for f in files:

            if not os.path.exists(f):
                print(f"[WARN] Skipping missing file in ZIP: {f}", file=sys.stderr)
                continue

            z.write(
                f,
                os.path.basename(f)
            )
