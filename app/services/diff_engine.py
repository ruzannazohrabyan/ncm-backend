import difflib


def compute_diff(before: str, after: str) -> str:
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)

    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile="before",
        tofile="after",
        lineterm="",
    )
    return "".join(diff)


def compute_diff_html(before: str, after: str) -> str:
    before_lines = before.splitlines()
    after_lines = after.splitlines()

    differ = difflib.HtmlDiff(wrapcolumn=120)
    return differ.make_table(before_lines, after_lines, fromdesc="Before", todesc="After")


def has_changes(before: str, after: str) -> bool:
    return before.strip() != after.strip()
