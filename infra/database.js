import retry from 'async-retry';
import { Pool, Client } from 'pg';
import snakeize from 'snakeize';

import { ServiceError } from 'errors/index.js';
import logger from 'infra/logger.js';

const configurations = {
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DB,
  password: process.env.POSTGRES_PASSWORD,
  port: process.env.POSTGRES_PORT,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 1,
  ssl: {
    rejectUnauthorized: false,
  },
  allowExitOnIdle: true,
};

// https://github.com/filipedeschamps/tabnews.com.br/issues/84
if (['test', 'development'].includes(process.env.NODE_ENV) || process.env.CI) {
  delete configurations.ssl;
}

const cache = {
  pool: null,
  maxConnections: null,
  reservedConnections: null,
  openedConnections: null,
  openedConnectionsLastUpdate: null,
};

async function query(query, options = {}) {
  let client;

  try {
    client = options.transaction ? options.transaction : await tryToGetNewClientFromPool();
    return await client.query(query);
  } catch (error) {
    throw parseQueryErrorAndLog(error, query);
  } finally {
    if (client && !options.transaction) {
      const tooManyConnections = await checkForTooManyConnections(client);

      if (tooManyConnections) {
        client.release();
        await cache.pool.end();
        cache.pool = null;
      } else {
        client.release();
      }
    }
  }
}

async function tryToGetNewClientFromPool() {
  const clientFromPool = await retry(newClientFromPool, {
    retries: 50,
    minTimeout: 0,
    factor: 2,
  });

  return clientFromPool;

  async function newClientFromPool() {
    if (!cache.pool) {
      cache.pool = new Pool(configurations);
    }

    return await cache.pool.connect();
  }
}

async function checkForTooManyConnections(client) {
  const currentTime = new Date().getTime();
  const openedConnectionsMaxAge = 10000;
  const maxConnectionsTolerance = 0.9;

  if (cache.maxConnections === null || cache.reservedConnections === null) {
    const [maxConnections, reservedConnections] = await getConnectionLimits();
    cache.maxConnections = maxConnections;
    cache.reservedConnections = reservedConnections;
  }

  if (
    !cache.openedConnections === null ||
    !cache.openedConnectionsLastUpdate === null ||
    currentTime - cache.openedConnectionsLastUpdate > openedConnectionsMaxAge
  ) {
    const openedConnections = await getOpenedConnections();
    cache.openedConnections = openedConnections;
    cache.openedConnectionsLastUpdate = currentTime;
  }

  if (cache.openedConnections > (cache.maxConnections - cache.reservedConnections) * maxConnectionsTolerance) {
    return true;
  }

  return false;

  async function getConnectionLimits() {
    const [maxConnectionsResult, reservedConnectionResult] = await client.query(
      'SHOW max_connections; SHOW superuser_reserved_connections;'
    );
    return [
      maxConnectionsResult.rows[0].max_connections,
      reservedConnectionResult.rows[0].superuser_reserved_connections,
    ];
  }

  async function getOpenedConnections() {
    const openConnectionsResult = await client.query({
      text: 'SELECT numbackends as opened_connections FROM pg_stat_database where datname = $1',
      values: [process.env.POSTGRES_DB],
    });
    return openConnectionsResult.rows[0].opened_connections;
  }
}

async function getNewClient() {
  try {
    const client = await tryToGetNewClient();
    return client;
  } catch (error) {
    const errorObject = new ServiceError({
      message: error.message,
      errorLocationCode: 'INFRA:DATABASE:GET_NEW_CONNECTED_CLIENT',
      stack: new Error().stack,
    });
    logger.error(snakeize(errorObject));
    throw errorObject;
  }
}

async function tryToGetNewClient() {
  const client = await retry(newClient, {
    retries: 50,
    minTimeout: 0,
    factor: 2,
  });

  return client;

  // You need to close the client when you are done with it
  // using the client.end() method.
  async function newClient() {
    const client = new Client(configurations);
    await client.connect();
    return client;
  }
}

function parseQueryErrorAndLog(error, query) {
  const expectedErrorsCode = [
    '23505', // unique constraint violation
  ];

  if (['test', 'development'].includes(process.env.NODE_ENV) || process.env.CI) {
    expectedErrorsCode.push('42883'); // undefined_function
  }

  const errorToReturn = new ServiceError({
    message: error.message,
    context: {
      query: query.text,
    },
    errorLocationCode: 'INFRA:DATABASE:QUERY',
    databaseErrorCode: error.code,
  });

  if (!expectedErrorsCode.includes(error.code)) {
    logger.error(snakeize(errorToReturn));
  }

  return errorToReturn;
}

async function transaction() {
  return await tryToGetNewClientFromPool();
}

export default Object.freeze({
  query,
  getNewClient,
  transaction,
});
