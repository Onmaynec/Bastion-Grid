"""Read a literal version, without importing repository application code into release tooling."""
import ast
import os
import re
from pathlib import Path


def version_tag():
    module = ast.parse(Path('bastion/__init__.py').read_text(encoding='utf-8'))
    versions = [ast.literal_eval(node.value) for node in module.body
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__version__'
                                                        for t in node.targets)]
    if len(versions) != 1 or not isinstance(versions[0], str) or not re.fullmatch(r'\d+\.\d+\.\d+', versions[0]):
        raise ValueError('A single numeric semantic version is required')
    return 'v'+versions[0]


if __name__ == '__main__':
    tag = version_tag()
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8', newline='\n') as output:
        output.write('tag='+tag+'\n')
    print(tag)
