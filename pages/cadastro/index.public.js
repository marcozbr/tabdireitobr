import { useState, useRef } from 'react';
import { useRouter } from 'next/router';
import { DefaultLayout, EmailInput, PasswordInput, suggestEmail } from 'pages/interface/index.js';
import { FormControl, Box, Heading, Button, TextInput, Flash } from '@primer/react';

export default function Register() {
  return (
    <DefaultLayout containerWidth="small" metadata={{ title: 'Cadastro' }}>
      <Heading as="h1" sx={{ mb: 3 }}>
        Cadastro
      </Heading>

      <SignUpForm />
    </DefaultLayout>
  );
}

function SignUpForm() {
  const router = useRouter();

  const usernameRef = useRef('');
  const emailRef = useRef('');
  const passwordRef = useRef('');

  const [globalErrorMessage, setGlobalErrorMessage] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorObject, setErrorObject] = useState(undefined);

  function clearErrors() {
    setErrorObject(undefined);
  }

  async function handleSubmit(event) {
    event.preventDefault();

    const username = usernameRef.current.value;
    const email = emailRef.current.value;
    const password = passwordRef.current.value;

    setIsLoading(true);
    setErrorObject(undefined);

    const suggestedEmail = suggestEmail(email);

    if (suggestedEmail) {
      setErrorObject({
        suggestion: suggestedEmail,
        key: 'email',
        type: 'typo',
      });

      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`/api/v1/users`, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username,
          email: email,
          password: password,
        }),
      });

      setGlobalErrorMessage(undefined);

      const responseBody = await response.json();

      if (response.status === 201) {
        localStorage.setItem('registrationEmail', email);
        router.push('/cadastro/confirmar');
        return;
      }

      if (response.status === 400) {
        setErrorObject(responseBody);
        setIsLoading(false);
        return;
      }

      if (response.status >= 403) {
        setGlobalErrorMessage(`${responseBody.message} Informe ao suporte este valor: ${responseBody.error_id}`);
        setIsLoading(false);
        return;
      }
    } catch (error) {
      setGlobalErrorMessage('Não foi possível se conectar ao TabNews. Por favor, verifique sua conexão.');
      setIsLoading(false);
    }
  }

  return (
    <form style={{ width: '100%' }} onSubmit={handleSubmit}>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {globalErrorMessage && <Flash variant="danger">{globalErrorMessage}</Flash>}

        <FormControl id="username">
          <FormControl.Label>Nome de usuário</FormControl.Label>
          <TextInput
            ref={usernameRef}
            onChange={clearErrors}
            name="username"
            size="large"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            block={true}
            aria-label="Seu nome de usuário"
          />
          {errorObject?.key === 'username' && (
            <FormControl.Validation variant="error">{errorObject.message}</FormControl.Validation>
          )}

          {errorObject?.type === 'string.alphanum' && (
            <FormControl.Caption>Dica: use somente letras e números, por exemplo: nomeSobrenome4 </FormControl.Caption>
          )}
        </FormControl>

        <EmailInput
          inputRef={emailRef}
          id="email"
          name="email"
          label="Email"
          errorObject={errorObject}
          setErrorObject={setErrorObject}
        />

        <PasswordInput
          inputRef={passwordRef}
          id="password"
          name="password"
          label="Senha"
          errorObject={errorObject}
          setErrorObject={setErrorObject}
        />

        <FormControl>
          <FormControl.Label visuallyHidden>Criar cadastro</FormControl.Label>
          <Button
            variant="primary"
            size="large"
            type="submit"
            disabled={isLoading}
            sx={{ width: '100%' }}
            aria-label="Criar cadastro">
            Criar cadastro
          </Button>
        </FormControl>
      </Box>
    </form>
  );
}
