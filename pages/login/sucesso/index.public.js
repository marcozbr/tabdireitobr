import { Box, Heading, Text } from '@primer/react';
import { ConfettiScreen, DefaultLayout } from 'pages/interface/index.js';

export default function ConfirmSignup() {
  return (
    <>
      <style>{`
        body {
          overflow-x: hidden;
          overflow-y: hidden;
        }
      `}</style>
      <div className="pl-3 pr-3">
        <ConfettiScreen showConfetti={true} />
      </div>

      <DefaultLayout containerWidth="medium" metadata={{ title: 'Confirme seu email' }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%', mt: 10 }}>
          <Heading as="h1" sx={{ textAlign: 'center' }}>
            Seu login foi realizado com sucesso!
          </Heading>
          <Text sx={{ textAlign: 'center' }}>
            E pedimos que aguarde por novas features para poder usar o seu usuário dentro do TabNews :)
          </Text>
        </Box>
      </DefaultLayout>
    </>
  );
}
