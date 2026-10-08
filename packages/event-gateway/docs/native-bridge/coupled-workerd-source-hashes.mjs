import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {isAbsolute, relative, sep} from 'node:path';

export function sourceHashes(paths, roots) {
  // Operator-selected checkout and fixture roots; resolve symlinks before containment.
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Resolve explicit operator-owned roots; no contents are read.
  const allowed = roots.map(root => fs.realpathSync(root)); // nosemgrep: javascript_pathtraversal_rule-non-literal-fs-filename
  const sources = paths.map(path => {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Resolve before enforcing the root boundary below; no contents are read.
    const source = fs.realpathSync(path); // nosemgrep: javascript_pathtraversal_rule-non-literal-fs-filename
    const contained = allowed.some(root => {
      const child = relative(root, source);
      return child !== '..' && !child.startsWith(`..${sep}`) && !isAbsolute(child);
    });
    if (!contained) throw new Error('outside qualified source roots');
    return [path, source];
  });
  // Every source above is bounded before any source contents are read.
  return Object.fromEntries(sources.map(([path, source]) => [path,
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- All canonical sources were bounded to the explicit roots above.
    createHash('sha256').update(fs.readFileSync(source)).digest('hex')])); // nosemgrep: javascript_pathtraversal_rule-non-literal-fs-filename
}
