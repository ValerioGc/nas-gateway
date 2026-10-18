import { execSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const steps = [
  ['Formatting code', 'cargo fmt'],
  ['Checking Rust formatting', 'cargo fmt --check'],
  ['Running clippy', 'cargo clippy --all-targets -- -D warnings'],
  ['Running Rust tests', 'cargo test'],
  ['Running installation script tests', 'npm run test:scripts'],
  ['Building the release binary', 'cargo build --release --locked'],
  ['Building the release package', 'npm run release:package'],
];

export function prepareRelease() {
  steps.forEach(([label, command], index) => {
    console.log(`\n▶ ${index + 1}/${steps.length} | ${label}`);
    execSync(command, { stdio: 'inherit' });
  });

  console.log('\n✅ Release preparation complete.');
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    prepareRelease();
  } catch {
    console.error('\n❌ Release preparation failed.');
    process.exit(1);
  }
}
