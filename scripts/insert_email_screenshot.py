# -*- coding: utf-8 -*-
"\"\"\"Insert email detail screenshot description into README safely.\"\"\""

def main():
    path = "README.md"
    with open(path, "r") as handle:
        text = handle.read().decode('cp1252')

    insert = (
        "3. **Email detail** – AI summary, label picker, and Gmail header metadata with masked addresses.\n"
        "   ![Email detail with AI summary](docs/images/email-detail.png)\n"
    )

    marker = "2. **Dashboard + detail view"
    if marker not in text:
        raise SystemExit("Expected screenshot block not found.")
    if "3. **Email detail**" in text:
        return

    parts = text.split(marker, 1)
    before = parts[0] + marker
    after = parts[1]
    after = insert + after
    new_text = before + after

    with open(path, "w") as handle:
        handle.write(new_text.encode('cp1252'))


if __name__ == "__main__":
    main()
