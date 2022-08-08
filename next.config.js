module.exports = {
  pageExtensions: ['public.js'],
  poweredByHeader: false,
  eslint: {
    ignoreDuringBuilds: true,
  },
  experimental: {
    nftTracing: true,
  },
  compiler: {
    styledComponents: true,
  },
  i18n: {
    locales: ['pt-br'],
    defaultLocale: 'pt-br',
  },
};
