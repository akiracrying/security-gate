// Intentionally vulnerable file for PR gate demo
// This file contains a synthetic AWS key to trigger Gitleaks (verified pattern)

const config = {
  region: "us-east-1",
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

module.exports = config;
