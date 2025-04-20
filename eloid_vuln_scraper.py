import ast
import clang.cindex
import javalang
import esprima
import requests
import re
import json
from typing import Dict, List, Set, Any
from dataclasses import dataclass

@dataclass
class Vulnerability:
    file: str
    line: int
    type: str
    description: str
    confidence: float
    cve_id: str = None

class EloidVulnScraper:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.language_patterns = {
            'python': [
                (r'eval\s*\(', 'Insecure use of eval', 0.9),
                (r'os\.system\s*\(', 'Potential command injection', 0.85)
            ],
            'cpp': [
                (r'strcpy\s*\(', 'Potential buffer overflow', 0.95),
                (r'gets\s*\(', 'Unsafe input function', 0.9)
            ],
            'c': [
                (r'strcpy\s*\(', 'Potential buffer overflow', 0.95),
                (r'gets\s*\(', 'Unsafe input function', 0.9)
            ],
            'javascript': [
                (r'eval\s*\(', 'Insecure use of eval', 0.9),
                (r'document\.write\s*\(', 'Potential XSS', 0.8)
            ],
            'java': [
                (r'Runtime\.getRuntime\(\)\.exec\(', 'Potential command injection', 0.9)
            ],
            'go': [
                (r'os\.Exec\s*\(', 'Potential command injection', 0.85)
            ],
            'rust': [
                (r'unsafe\s*{', 'Unsafe code block', 0.8)
            ]
        }
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def parse_python(self, file_path: str) -> ast.AST:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        return ast.parse(source), file_path

    def parse_c_cpp(self, file_path: str) -> Any:
        index = clang.cindex.Index.create()
        tu = index.parse(file_path, args=['-std=c++11'] if file_path.endswith('.cpp') else ['-std=c99'])
        return tu.cursor, file_path

    def parse_javascript(self, file_path: str) -> Dict:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        return esprima.parseScript(source, loc=True), file_path

    def parse_java(self, file_path: str) -> javalang.ast.Node:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        return javalang.parse.parse(source), file_path

    def parse_go(self, file_path: str) -> Any:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        return go_parser.parse(source), file_path  # Hypothetical

    def parse_rust(self, file_path: str) -> Any:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        return syn.parse_file(source), file_path  # Hypothetical

    def analyze_python(self, tree: ast.AST, file_path: str):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                for pattern, desc, conf in self.language_patterns['python']:
                    if re.search(pattern, ast.unparse(node)):
                        self.vulnerabilities.append(Vulnerability(
                            file=file_path,
                            line=node.lineno,
                            type='Pattern Match',
                            description=desc,
                            confidence=conf
                        ))

    def analyze_c_cpp(self, cursor: Any, file_path: str, lang: str):
        def traverse(cursor):
            if cursor.kind.is_expression():
                source = cursor.spelling or cursor.displayname
                for pattern, desc, conf in self.language_patterns[lang]:
                    if re.search(pattern, source):
                        self.vulnerabilities.append(Vulnerability(
                            file=file_path,
                            line=cursor.location.line,
                            type='Pattern Match',
                            description=desc,
                            confidence=conf
                        ))
            for child in cursor.get_children():
                traverse(child)
        traverse(cursor)

    def analyze_javascript(self, tree: Dict, file_path: str):
        def traverse(node):
            if hasattr(node, 'type') and node.type == 'CallExpression':
                source = esprima.toStr(node)
                for pattern, desc, conf in self.language_patterns['javascript']:
                    if re.search(pattern, source):
                        self.vulnerabilities.append(Vulnerability(
                            file=file_path,
                            line=node.loc.start.line,
                            type='Pattern Match',
                            description=desc,
                            confidence=conf
                        ))
            for child in node.get('body', []):
                traverse(child)
        traverse(tree)

    def analyze_java(self, tree: javalang.ast.Node, file_path: str):
        for path, node in javalang.ast.walk_tree(tree):
            if isinstance(node, javalang.tree.MethodInvocation):
                source = str(node)
                for pattern, desc, conf in self.language_patterns['java']:
                    if re.search(pattern, source):
                        self.vulnerabilities.append(Vulnerability(
                            file=file_path,
                            line=node.position.line,
                            type='Pattern Match',
                            description=desc,
                            confidence=conf
                        ))

    def analyze_go(self, tree: Any, file_path: str):
        # Hypothetical Go analysis
        for node in tree.nodes:  # Simplified
            source = str(node)
            for pattern, desc, conf in self.language_patterns['go']:
                if re.search(pattern, source):
                    self.vulnerabilities.append(Vulnerability(
                        file=file_path,
                        line=node.line,
                        type='Pattern Match',
                        description=desc,
                        confidence=conf
                    ))

    def analyze_rust(self, tree: Any, file_path: str):
        # Hypothetical Rust analysis
        for node in tree.items:  # Simplified
            source = str(node)
            for pattern, desc, conf in self.language_patterns['rust']:
                if re.search(pattern, source):
                    self.vulnerabilities.append(Vulnerability(
                        file=file_path,
                        line=node.line,
                        type='Pattern Match',
                        description=desc,
                        confidence=conf
                    ))

    def query_nvd(self, keyword: str) -> Set[str]:
        try:
            response = requests.get(f"{self.nvd_api_url}?keywordSearch={keyword}")
            if response.status_code == 200:
                data = response.json()
                return {cve['id'] for cve in data.get('vulnerabilities', [])}
        except Exception as e:
            print(f"NVD query failed: {e}")
        return set()

    def scan_file(self, file_path: str):
        ext = file_path.split('.')[-1]
        lang = {
            'py': ('python', self.parse_python, self.analyze_python),
            'cpp': ('cpp', self.parse_c_cpp, lambda t, p: self.analyze_c_cpp(t, p, 'cpp')),
            'c': ('c', self.parse_c_cpp, lambda t, p: self.analyze_c_cpp(t, p, 'c')),
            'js': ('javascript', self.parse_javascript, self.analyze_javascript),
            'java': ('java', self.parse_java, self.analyze_java),
            'go': ('go', self.parse_go, self.analyze_go),
            'rs': ('rust', self.parse_rust, self.analyze_rust)
        }.get(ext)
        if lang:
            tree, path = lang[1](file_path)
            lang[2](tree, path)
        else:
            print(f"Unsupported file extension: {ext}")

    def generate_report(self) -> str:
        report = {"vulnerabilities": [vars(vuln) for vuln in self.vulnerabilities]}
        return json.dumps(report, indent=2)

def main():
    scraper = EloidVulnScraper()
    # Example usage
    for file in ["example.py", "example.cpp", "example.c", "example.js", "example.java", "example.go", "example.rs"]:
        scraper.scan_file(file)
    print(scraper.generate_report())

if __name__ == "__main__":
    main()
