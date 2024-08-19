import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';

import { Box, Link, Text, Tooltip } from '@/TabNewsUI';
import { LinkExternalIcon } from '@/TabNewsUI/icons';
import { getDomain, isExternalLink, isTrustedDomain } from 'pages/interface';

export default function AdBanner({ ad: newAd, ...props }) {
  const [ad, setAd] = useState(newAd);
  const router = useRouter();

  const link = ad.source_url || `/${ad.owner_username}/${ad.slug}`;
  const isAdToExternalLink = isExternalLink(link);
  const domain = isAdToExternalLink ? `(${getDomain(link)})` : '';
  const title = ad.title.length > 70 ? ad.title.substring(0, 67).trim().concat('...') : ad.title;

  useEffect(() => {
    setAd(newAd);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.asPath]);

  return (
    <Box {...props} as="aside" sx={{ display: 'grid', ...props.sx }}>
      <Box>
        <Link
          sx={{
            overflow: 'auto',
            fontWeight: 'semibold',
            wordWrap: 'break-word',
            ':link': {
              color: 'success.fg',
            },
            ':visited': {
              color: 'success.fg',
            },
          }}
          href={link}
          rel={isTrustedDomain(link) ? undefined : 'nofollow'}>
          <Text sx={{ wordBreak: 'break-word', marginRight: 1 }}>
            {title} {domain}
          </Text>
          {isAdToExternalLink && <LinkExternalIcon verticalAlign="middle" />}
        </Link>
      </Box>

      <Text sx={{ whiteSpace: 'nowrap', overflow: 'hidden', fontSize: 0, color: 'neutral.emphasis' }}>
        Contribuindo com{' '}
        <Tooltip text={`Autor: ${ad.owner_username}`} direction="nw" sx={{ position: 'absolute', display: 'grid' }}>
          <Link
            sx={{ overflow: 'hidden', textOverflow: 'ellipsis', color: 'neutral.emphasis', mr: 2 }}
            href={`/${ad.owner_username}`}>
            {ad.owner_username}
          </Link>
        </Tooltip>
      </Text>
    </Box>
  );
}
