#!/usr/bin/env python3

import json
from collections import defaultdict
from typing import Dict, List, Any

class CategoryNode:
    def __init__(self, name: str, level: int):
        self.name = name
        self.level = level
        self.links: List[Dict[str, Any]] = []
        self.subcategories: Dict[str, 'CategoryNode'] = {}

def create_anchor(text: str) -> str:
    """Create GitHub-style anchor links."""
    return text.lower().replace(' & ', '--').replace(' ', '-')

def build_category_tree(links: List[Dict[str, Any]]) -> Dict[str, CategoryNode]:
    root_categories: Dict[str, CategoryNode] = {}
    for link in links:
        path = link['path']
        if path[0] in ["Reading List", "FOSS"]:
            continue
        current_level = root_categories
        current_node = None
        heading_level = 1
        for category in path:
            if category not in current_level:
                current_level[category] = CategoryNode(category, heading_level)
            current_node = current_level[category]
            current_level = current_node.subcategories
            heading_level += 1
        if current_node:
            current_node.links.append(link)
    return root_categories

def generate_toc(categories: Dict[str, CategoryNode], indent_level: int = 0) -> str:
    """Generate table of contents with proper indentation and anchor links."""
    toc = []
    indent = "    " * indent_level
    for category in sorted(categories.values(), key=lambda x: x.name):
        anchor = create_anchor(category.name)
        toc.append(f"{indent}- [{category.name}](#{anchor})")
        if category.subcategories:
            toc.append(generate_toc(category.subcategories, indent_level + 1))
    return '\n'.join(toc)

def generate_markdown(categories: Dict[str, CategoryNode], output_file: str):
    def write_category(f, category: CategoryNode):
        # Write category heading
        f.write(f"{'#' * category.level} {category.name}\n\n")
        # Write links table if there are any links
        if category.links:
            f.write("| Name | Description |\n")
            f.write("|------|-------------|\n")
            for link in category.links:
                name = link['name'].replace('|', '\\|')
                if "description" in link:
                    description = link['description'].replace('|', '\\|')
                else:
                    description = ""
                url = link['url']
                f.write(f"| [{name}]({url}) | {description} |\n")
            f.write("\n")
        # Write subcategories
        for subcategory in sorted(category.subcategories.values(), key=lambda x: x.name):
            write_category(f, subcategory)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        # Write table of contents
        f.write("Table of Contents &rarr;\n\n")
        f.write(generate_toc(categories))
        f.write("\n\n")
        # Write categories and their content
        for category in sorted(categories.values(), key=lambda x: x.name):
            write_category(f, category)

def main():
    with open('linksnapper.json', 'r', encoding='utf-8') as f:
        links = json.load(f)
    categories = build_category_tree(links)
    generate_markdown(categories, 'output.md')
    print("README generation complete. Output saved to output.md")

if __name__ == '__main__':
    main()
