#!/usr/bin/env python3

import argparse
import json
import re
from typing import Dict, List, Any


class CategoryNode:
    def __init__(self, name: str, level: int):
        self.name = name
        self.level = level
        self.links: List[Dict[str, Any]] = []
        self.subcategories: Dict[str, "CategoryNode"] = {}
        self.full_path: List[str] = []


def slugify(text: str) -> str:
    """Convert text to a GitHub-compatible anchor slug."""
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)  # strip non-word chars except hyphens
    text = re.sub(r"[\s]+", "-", text)  # collapse whitespace to hyphens
    text = re.sub(r"-+", "-", text)  # collapse multiple hyphens
    return text.strip("-")


def create_anchor(path: List[str]) -> str:
    """Create a unique anchor from the full category path."""
    return "-".join(slugify(part) for part in path)


def build_category_tree(
    links: List[Dict[str, Any]], skip_categories: List[str]
) -> Dict[str, CategoryNode]:
    root_categories: Dict[str, CategoryNode] = {}
    for link in links:
        path = link["path"]
        if path[0] in skip_categories:
            continue
        current_level = root_categories
        current_node = None
        heading_level = 1
        current_path = []
        for category in path:
            current_path.append(category)
            if category not in current_level:
                current_level[category] = CategoryNode(category, heading_level)
                current_level[category].full_path = current_path.copy()
            current_node = current_level[category]
            current_level = current_node.subcategories
            heading_level += 1
        if current_node:
            current_node.links.append(link)
    return root_categories


def generate_toc(categories: Dict[str, CategoryNode], indent_level: int = 0) -> str:
    """Generate table of contents with unique anchor links."""
    lines = []
    indent = "    " * indent_level
    for category in sorted(categories.values(), key=lambda x: x.name):
        anchor = create_anchor(category.full_path)
        lines.append(f"{indent}- [{category.name}](#{anchor})")
        if category.subcategories:
            lines.append(generate_toc(category.subcategories, indent_level + 1))
    return "\n".join(lines)


def write_category(f, category: CategoryNode):
    """Write a category heading, its links table, and recurse into subcategories."""
    anchor = create_anchor(category.full_path)
    hashes = "#" * category.level
    f.write(f'{hashes} <a id="{anchor}"></a> {category.name}\n\n')

    if category.links:
        f.write("| Name | Description |\n")
        f.write("|------|-------------|\n")
        for link in sorted(category.links, key=lambda x: x["name"].lower()):
            name = link["name"].replace("|", "\\|")
            description = link.get("description", "").replace("|", "\\|")
            url = link["url"]
            f.write(f"| [{name}]({url}) | {description} |\n")
        f.write("\n")

    for sub in sorted(category.subcategories.values(), key=lambda x: x.name):
        write_category(f, sub)


def generate_markdown(
    categories: Dict[str, CategoryNode], output_file: str, header: str
):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("## Table of Contents\n\n")
        f.write(generate_toc(categories))
        f.write("\n\n---\n\n")
        for category in sorted(categories.values(), key=lambda x: x.name):
            write_category(f, category)


def main():
    parser = argparse.ArgumentParser(
        description="Convert LinkSnapper JSON export to a Markdown README."
    )
    parser.add_argument(
        "-i",
        "--input",
        default="linksnapper.json",
        help="Path to LinkSnapper JSON file (default: linksnapper.json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="README.md",
        help="Output Markdown file (default: README.md)",
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        default=["Reading List", "FOSS"],
        help='Top-level categories to skip (default: "Reading List" "FOSS")',
    )
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        links = json.load(f)

    header = """\
<p align="center">
<img src=".github/assets/logo.svg" alt="LinkHub Logo" width="250" height="250" />
</p>
<h1 align="center">Cybersecurity Links Dump</h1>

"""

    categories = build_category_tree(links, args.skip)
    generate_markdown(categories, args.output, header)
    print(f"Done — wrote {args.output}")


if __name__ == "__main__":
    main()
