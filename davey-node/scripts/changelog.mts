import fs from 'fs';
import path from 'path';
import packageJson from '../package.json';

const currentVersion = packageJson.version;
if (!currentVersion) throw new Error("Can't detect library version.");

// @ts-ignore
const changelogPath = path.resolve(import.meta.dirname, '../CHANGELOG.md');
const changelog = fs.readFileSync(changelogPath, { encoding: 'utf-8' });
if (changelog.includes(`## [${currentVersion}]`)) throw new Error('Current version has already been documented.');
let futureChangelog = '';

// Add version section
let arr = changelog.split('## [Unreleased]');
arr[1] =
  `

## [${currentVersion}] - ${new Date().toISOString().slice(0, 10)}

` + arr[1];
futureChangelog = arr.join('## [Unreleased]');

const lastVersion = changelog.match(/\n## \[(\d+\.\d+\.\d+)\] - /)?.[1];
if (!lastVersion) throw new Error("Can't find last version in changelog.");

const lastLine = `[${currentVersion}]: https://github.com/Snazzah/davey/compare/v${lastVersion}...v${currentVersion}`;
console.log({ lastVersion });

// Update footer
arr = futureChangelog
  .split('\n')
  .map((line) =>
    line.startsWith('[unreleased]: https://github.com')
      ? `[unreleased]: https://github.com/Snazzah/davey/compare/v${currentVersion}...HEAD\n${lastLine}`
      : line,
  );

futureChangelog = arr.join('\n');

fs.writeFileSync(changelogPath, futureChangelog);
