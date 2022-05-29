import { ThemeProvider, BaseStyles, SSRProvider } from '@primer/react';
import { SWRConfig } from 'swr';

import '../styles/bytemd.css';
import '../styles/github.scss';

async function SWRFetcher(resource, init) {
  const response = await fetch(resource, init);
  const responseBody = await response.json();

  return responseBody;
}

function MyApp({ Component, pageProps }) {
  return (
    <SWRConfig
      value={{
        fetcher: SWRFetcher,
      }}>
      <SSRProvider>
        <ThemeProvider preventSSRMismatch>
          <BaseStyles>
            <Component {...pageProps} />
          </BaseStyles>
        </ThemeProvider>
      </SSRProvider>
    </SWRConfig>
  );
}

export default MyApp;
