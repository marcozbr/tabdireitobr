import { UnprocessableEntityError } from 'errors';
import database from 'infra/database.js';

const tableNameMap = {
  'user:tabcoin': 'user_tabcoin_operations',
  'user:tabcash': 'user_tabcash_operations',
  'sponsored_content:tabcoin': 'sponsored_content_tabcoin_operations',
  'sponsored_content:tabcash': 'sponsored_content_tabcash_operations',
  default: 'content_tabcoin_operations',
};

const balanceTypeMap = {
  'content:tabcoin:credit': 'credit',
  'content:tabcoin:debit': 'debit',
  default: 'initial',
};

const sqlFunctionMap = {
  'user:tabcoin': 'get_user_current_tabcoins',
  'user:tabcash': 'get_user_current_tabcash',
  'sponsored_content:tabcoin': 'get_sponsored_content_current_tabcoins',
  'sponsored_content:tabcash': 'get_sponsored_content_current_tabcash',
  default: 'get_content_current_tabcoins',
};

async function findAllByOriginatorId(originatorId, options) {
  const query = {
    text: `
      SELECT * FROM (
        SELECT id, recipient_id, amount, originator_type, originator_id,
          'user:tabcoin' AS balance_type
        FROM user_tabcoin_operations
        WHERE originator_id = $1
      UNION ALL
        SELECT id, recipient_id, amount, originator_type, originator_id,
          'user:tabcash' AS balance_type
        FROM user_tabcash_operations
        WHERE originator_id = $1
      UNION ALL
        SELECT id, recipient_id, amount, originator_type, originator_id,
          CONCAT('content:tabcoin:', balance_type) AS balance_type
        FROM content_tabcoin_operations
        WHERE originator_id = $1
      ) AS all_operations;
    `,
    values: [originatorId],
  };

  const results = await database.query(query, options);
  return results.rows;
}

async function create({ balanceType, recipientId, amount, originatorType, originatorId }, options = {}) {
  const tableName = tableNameMap[balanceType] || tableNameMap.default;
  const hasBalanceTypeColum = balanceType.startsWith('content:tabcoin');

  const query = {
    text: `
      INSERT INTO ${tableName}
        (recipient_id, amount, originator_type, originator_id${hasBalanceTypeColum ? ', balance_type' : ''})
      VALUES
        ($1, $2, $3, $4${hasBalanceTypeColum ? ', $5' : ''})
      RETURNING * ;
      `,
    values: [recipientId, amount, originatorType, originatorId],
  };

  if (hasBalanceTypeColum) {
    const parsedBalanceType = balanceTypeMap[balanceType] || balanceTypeMap.default;

    query.values.push(parsedBalanceType);
  }

  const results = await database.query(query, options);
  return results.rows[0];
}

async function getTotal({ balanceType, recipientId }, options) {
  const sqlFunction = sqlFunctionMap[balanceType] || sqlFunctionMap.default;

  const query = {
    text: `SELECT ${sqlFunction}($1) AS total;`,
    values: [recipientId],
  };

  const results = await database.query(query, options);
  return results.rows[0].total;
}

async function getContentTabcoinsCreditDebit({ recipientId }, options = {}) {
  const query = {
    text: `
      SELECT
        COALESCE(cb.total_balance, get_sponsored_content_current_tabcoins(sc.id)) AS total_balance,
        COALESCE(cb.total_credit, 0) AS total_credit,
        COALESCE(cb.total_debit, 0) AS total_debit
      FROM contents c
      LEFT JOIN sponsored_contents sc ON c.status = 'sponsored' AND c.id = sc.content_id
      LEFT JOIN LATERAL get_content_balance_credit_debit(c.id) cb ON c.status <> 'sponsored'
      WHERE c.id = $1
    ;`,
    values: [recipientId],
  };

  const results = await database.query(query, options);
  return {
    tabcoins: results.rows[0].total_balance,
    tabcoins_credit: results.rows[0].total_credit,
    tabcoins_debit: results.rows[0].total_debit,
  };
}

async function rateContent({ contentId, contentOwnerId, fromUserId, transactionType }, options = {}) {
  const tabCoinsToDebitFromUser = -2;
  const tabCashToCreditToUser = 1;
  const tabCoinsToTransactToContentOwner = transactionType === 'credit' ? 1 : -1;
  const tabCoinsToTransactToContent = transactionType === 'credit' ? 1 : -1;
  const originatorType = 'event';
  const originatorId = options.eventId;

  const query = {
    text: `
      WITH users_tabcoin_inserts AS (
        INSERT INTO user_tabcoin_operations
          (recipient_id, amount, originator_type, originator_id)
        VALUES
          ($1, $2, $8, $9),
          ($6, $7, $8, $9)
        RETURNING
          *
      ),
      users_tabcash_insert AS (
        INSERT INTO user_tabcash_operations
          (recipient_id, amount, originator_type, originator_id)
        VALUES
          ($1, $3, $8, $9)
      ),
      content_insert AS (
        INSERT INTO content_tabcoin_operations
          (balance_type, recipient_id, amount, originator_type, originator_id)
        VALUES
          ($10, $4, $5, $8, $9)
        RETURNING
          *
      )
      SELECT
        get_user_current_tabcoins($1) AS user_current_tabcoin_balance,
        tabcoins_count.total_balance as content_current_tabcoin_balance,
        tabcoins_count.total_credit as content_current_tabcoin_credit,
        tabcoins_count.total_debit as content_current_tabcoin_debit 
      FROM
        users_tabcoin_inserts,
        content_insert,
        get_content_balance_credit_debit(content_insert.recipient_id) tabcoins_count
      LIMIT
        1
    ;`,
    values: [
      fromUserId, // $1
      tabCoinsToDebitFromUser, // $2
      tabCashToCreditToUser, // $3

      contentId, // $4
      tabCoinsToTransactToContent, // $5

      contentOwnerId, // $6
      tabCoinsToTransactToContentOwner, // $7

      originatorType, // $8
      originatorId, // $9

      transactionType, // $10
    ],
  };

  const results = await database.query(query, options);
  const currentBalances = results.rows[0];

  if (currentBalances.user_current_tabcoin_balance < 0) {
    throw new UnprocessableEntityError({
      message: `Não foi possível adicionar TabCoins nesta publicação.`,
      action: `Você precisa de pelo menos ${Math.abs(tabCoinsToDebitFromUser)} TabCoins para realizar esta ação.`,
      errorLocationCode: 'MODEL:BALANCE:RATE_CONTENT:NOT_ENOUGH',
    });
  }

  return {
    tabcoins: currentBalances.content_current_tabcoin_balance,
    tabcoins_credit: currentBalances.content_current_tabcoin_credit,
    tabcoins_debit: currentBalances.content_current_tabcoin_debit,
  };
}

async function sponsorContent({ sponsoredContentId, contentOwnerId, tabcash }, options) {
  const originatorType = 'event';
  const originatorId = options.eventId;
  const tabcoins = 1;
  const balanceType = 'initial';

  const query = {
    text: `
      WITH user_tabcash_insert AS (
        INSERT INTO user_tabcash_operations
          (recipient_id, amount, originator_type, originator_id)
        VALUES
          ($1, $2, $7, $8)
        RETURNING
          *
      ),
      sponsored_content_tabcash_insert AS (
        INSERT INTO sponsored_content_tabcash_operations
          (recipient_id, amount, originator_type, originator_id)
        VALUES
          ($3, $4, $7, $8)
        RETURNING
          *
      ),
      sponsored_content_tabcoin_insert AS (
        INSERT INTO sponsored_content_tabcoin_operations
          (recipient_id, balance_type, amount, originator_type, originator_id)
        VALUES
          ($3, $5, $6, $7, $8)
      )
      SELECT
        get_user_current_tabcash($1) AS user_current_tabcash_balance
      FROM
        user_tabcash_insert,
        sponsored_content_tabcash_insert
      LIMIT
        1
    ;`,
    values: [
      contentOwnerId, // $1
      tabcash * -1, // $2

      sponsoredContentId, // $3
      tabcash, // $4

      balanceType, // $5
      tabcoins, // $6

      originatorType, // $7
      originatorId, // $8
    ],
  };

  const results = await database.query(query, options);
  const currentBalances = results.rows[0];

  if (currentBalances.user_current_tabcash_balance < 0) {
    throw new UnprocessableEntityError({
      message: `Não foi possível utilizar TabCash para patrocinar esta publicação.`,
      action: `Você não possui ${tabcash} TabCash disponível.`,
      errorLocationCode: 'MODEL:BALANCE:SPONSOR_CONTENT:NOT_ENOUGH',
    });
  }

  return {
    user_tabcash: currentBalances.user_current_tabcash_balance,
    tabcoins: tabcoins,
  };
}

async function undo(balanceOperation, options) {
  const invertedBalanceOperation = {
    balanceType: balanceOperation.balance_type,
    recipientId: balanceOperation.recipient_id,
    amount: balanceOperation.amount * -1,
    originatorType: 'event',
    originatorId: options.event.id,
  };

  const newBalanceOperation = await create(invertedBalanceOperation, options);
  return newBalanceOperation;
}

export default Object.freeze({
  findAllByOriginatorId,
  create,
  getTotal,
  getContentTabcoinsCreditDebit,
  rateContent,
  sponsorContent,
  undo,
});
