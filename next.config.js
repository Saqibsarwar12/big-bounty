/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  serverExternalPackages: ['playwright-core', 'puppeteer-core'],
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals.push('playwright-core', 'puppeteer-core', 'kerberos', 'chromium-bidi');
    }
    return config;
  },
};
module.exports = nextConfig;
