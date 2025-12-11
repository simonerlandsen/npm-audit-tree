const https = require('https');
const fs = require('fs');
const path = require('path');

const pkg = require('../package.json');
const version = pkg.version;

const REPO = 'simonerlandsen/npm-audit-tree';

function getPlatformBinary() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'darwin' && arch === 'arm64') {
    return 'npm-audit-tree-darwin-arm64';
  } else if (platform === 'darwin' && arch === 'x64') {
    return 'npm-audit-tree-darwin-x64';
  } else if (platform === 'linux' && arch === 'x64') {
    return 'npm-audit-tree-linux-x64';
  } else if (platform === 'win32' && arch === 'x64') {
    return 'npm-audit-tree-win32-x64.exe';
  } else {
    console.error(`Unsupported platform: ${platform}-${arch}`);
    process.exit(1);
  }
}

const ALLOWED_HOSTS = ['github.com', 'objects.githubusercontent.com'];
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 30000;

function download(url, dest) {
  return new Promise((resolve, reject) => {
    let file = null;
    let redirectCount = 0;

    const cleanup = () => {
      if (file) {
        file.close();
        fs.unlink(dest, () => {});
      }
    };

    const makeRequest = (requestUrl) => {
      const parsedUrl = new URL(requestUrl);

      if (!ALLOWED_HOSTS.includes(parsedUrl.host)) {
        cleanup();
        reject(new Error(`Redirect to untrusted host: ${parsedUrl.host}`));
        return;
      }

      const req = https.get(requestUrl, { timeout: TIMEOUT_MS }, (response) => {
        if (response.statusCode === 302 || response.statusCode === 301) {
          redirectCount++;
          if (redirectCount > MAX_REDIRECTS) {
            cleanup();
            reject(new Error('Too many redirects'));
            return;
          }
          makeRequest(response.headers.location);
          return;
        }

        if (response.statusCode !== 200) {
          cleanup();
          reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
          return;
        }

        file = fs.createWriteStream(dest);
        response.pipe(file);
        file.on('finish', () => {
          file.close();
          resolve();
        });
      });

      req.on('error', (err) => {
        cleanup();
        reject(err);
      });

      req.on('timeout', () => {
        req.destroy();
        cleanup();
        reject(new Error('Download timed out'));
      });
    };

    makeRequest(url);
  });
}

async function main() {
  const binaryName = getPlatformBinary();
  const url = `https://github.com/${REPO}/releases/download/v${version}/${binaryName}`;
  const binDir = path.join(__dirname, '..', 'bin');
  const dest = path.join(binDir, process.platform === 'win32' ? 'npm-audit-tree.exe' : 'npm-audit-tree');

  // Ensure bin directory exists
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  console.log(`Downloading ${binaryName}...`);

  try {
    await download(url, dest);

    // Make executable on Unix
    if (process.platform !== 'win32') {
      fs.chmodSync(dest, 0o755);
    }

    console.log('npm-audit-tree installed successfully!');
  } catch (err) {
    console.error(`Failed to download binary: ${err.message}`);
    console.error(`URL: ${url}`);
    console.error('You can build from source using: cargo install npm-audit-tree');
    process.exit(1);
  }
}

main();
