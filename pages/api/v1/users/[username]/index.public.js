import nextConnect from 'next-connect';

import { ForbiddenError, UnprocessableEntityError, ValidationError } from 'errors';
import database from 'infra/database.js';
import authentication from 'models/authentication.js';
import authorization from 'models/authorization.js';
import ban from 'models/ban.js';
import cacheControl from 'models/cache-control';
import controller from 'models/controller.js';
import event from 'models/event.js';
import otp from 'models/otp';
import user from 'models/user.js';
import validator from 'models/validator.js';

export default nextConnect({
  attachParams: true,
  onNoMatch: controller.onNoMatchHandler,
  onError: controller.onErrorHandler,
})
  .use(controller.injectRequestMetadata)
  .use(controller.logRequest)
  .get(cacheControl.swrMaxAge(10), getValidationHandler, getHandler)
  .patch(
    cacheControl.noCache,
    authentication.injectAnonymousOrUser,
    patchValidationHandler,
    authorization.canRequest('update:user'),
    patchHandler,
  )
  .delete(
    cacheControl.noCache,
    authentication.injectAnonymousOrUser,
    deleteValidationHandler,
    authorization.canRequest('ban:user'),
    deleteHandler,
  );

function getValidationHandler(request, response, next) {
  const cleanValues = validator(request.query, {
    username: 'required',
  });

  request.query = cleanValues;

  next();
}

async function getHandler(request, response) {
  const userTryingToGet = user.createAnonymous();
  const userStoredFromDatabase = await user.findOneByUsername(request.query.username, {
    withBalance: true,
  });

  const secureOutputValues = authorization.filterOutput(userTryingToGet, 'read:user', userStoredFromDatabase);

  return response.status(200).json(secureOutputValues);
}

function patchValidationHandler(request, response, next) {
  const cleanQueryValues = validator(request.query, {
    username: 'required',
  });

  request.query = cleanQueryValues;

  const cleanBodyValues = validator(request.body, {
    username: 'optional',
    email: 'optional',
    password: 'optional',
    description: 'optional',
    notifications: 'optional',
    totp: 'optional',
    totp_secret: 'optional',
  });

  request.body = cleanBodyValues;

  next();
}

async function patchHandler(request, response) {
  const userTryingToPatch = request.context.user;
  const targetUsername = request.query.username;
  const targetUser =
    targetUsername === userTryingToPatch.username ? userTryingToPatch : await user.findOneByUsername(targetUsername);
  const insecureInputValues = request.body;

  let updateAnotherUser = false;

  if (!authorization.can(userTryingToPatch, 'update:user', targetUser)) {
    if (!authorization.can(userTryingToPatch, 'update:user:others')) {
      throw new ForbiddenError({
        message: 'Você não possui permissão para atualizar outro usuário.',
        action: 'Verifique se você possui a feature "update:user:others".',
        errorLocationCode: 'CONTROLLER:USERS:USERNAME:PATCH:USER_CANT_UPDATE_OTHER_USER',
      });
    }

    updateAnotherUser = true;
  }

  const secureInputValues = authorization.filterInput(
    userTryingToPatch,
    updateAnotherUser ? 'update:user:others' : 'update:user',
    insecureInputValues,
    targetUser,
  );

  if (secureInputValues.totp_secret) {
    const userAlreadyEnabledTotp = targetUser.totp_secret !== null;

    if (userAlreadyEnabledTotp) {
      throw new ValidationError({
        message: 'Duplo fator de autenticação já habilitado para a conta.',
        action: 'Verifique se você está realizando a operação correta.',
        errorLocationCode: 'CONTROLLER:USERS:USERNAME:PATCH:MFA:TOTP:ALREADY_CONFIGURED',
      });
    } else {
      if (!secureInputValues.totp) {
        throw new ForbiddenError({
          message: 'O código TOTP não foi informado.',
          action: 'Refaça a requisição enviando um código TOTP.',
          errorLocationCode: 'CONTROLLER:USERS:USERNAME:PATCH:MFA:TOTP:TOKEN_NOT_SENT',
        });
      }

      const isTokenValid = otp.validateTotp(secureInputValues.totp_secret, secureInputValues.totp);

      if (!isTokenValid) {
        throw new ForbiddenError({
          message: 'O código TOTP informado é inválido.',
          action: 'Verifique o código TOTP enviado e tente novamente.',
          errorLocationCode: 'CONTROLLER:USERS:USERNAME:PATCH:MFA:TOTP:INVALID_CODE',
        });
      }
    }
  }

  // TEMPORARY BEHAVIOR
  // TODO: only let user update "password"
  // once we have double confirmation.
  delete secureInputValues.password;

  const transaction = await database.transaction();

  let updatedUser;

  try {
    await transaction.query('BEGIN');

    updatedUser = await user.update(targetUser, secureInputValues, {
      transaction: transaction,
    });

    await event.create(
      {
        type: 'update:user',
        originator_user_id: request.context.user.id,
        originator_ip: request.context.clientIp,
        metadata: getEventMetadata(targetUser, updatedUser),
      },
      {
        transaction: transaction,
      },
    );

    await transaction.query('COMMIT');
    await transaction.release();
  } catch (error) {
    await transaction.query('ROLLBACK');
    await transaction.release();

    if (error instanceof ValidationError && error.key === 'email') {
      updatedUser = {
        ...targetUser,
        updated_at: new Date(),
      };
    } else {
      throw error;
    }
  }

  const secureOutputValues = authorization.filterOutput(
    userTryingToPatch,
    updateAnotherUser ? 'read:user' : 'read:user:self',
    updatedUser,
  );

  return response.status(200).json(secureOutputValues);

  function getEventMetadata(originalUser, updatedUser) {
    const metadata = {
      id: originalUser.id,
      updatedFields: [],
    };

    const updatableFields = ['description', 'notifications', 'username', 'totp_secret'];
    for (const field of updatableFields) {
      if (originalUser[field] !== updatedUser[field]) {
        metadata.updatedFields.push(field);

        if (field === 'username') {
          metadata.username = {
            old: originalUser.username,
            new: updatedUser.username,
          };
        }
      }
    }

    return metadata;
  }
}

function deleteValidationHandler(request, response, next) {
  const cleanQueryValues = validator(request.query, {
    username: 'required',
  });

  request.query = cleanQueryValues;

  const cleanBodyValues = validator(request.body, {
    ban_type: 'required',
  });

  request.body = cleanBodyValues;

  next();
}

async function deleteHandler(request, response) {
  const userTryingToDelete = request.context.user;
  const targetUsername = request.query.username;
  const targetUser = await user.findOneByUsername(targetUsername);
  const insecureInputValues = request.body;
  const secureInputValues = authorization.filterInput(userTryingToDelete, 'ban:user', insecureInputValues);

  if (targetUser.features.includes('nuked')) {
    throw new UnprocessableEntityError({
      message: 'Este usuário já está banido permanentemente.',
      action: 'Verifique se você está tentando banir permanentemente o usuário correto.',
      errorLocationCode: 'CONTROLLER:USERS:USERNAME:DELETE:USER_ALREADY_NUKED',
    });
  }

  const transaction = await database.transaction();
  let nukedUser;

  try {
    await transaction.query('BEGIN');

    const currentEvent = await event.create(
      {
        type: 'ban:user',
        originator_user_id: request.context.user.id,
        originator_ip: request.context.clientIp,
        metadata: {
          ban_type: secureInputValues.ban_type,
          user_id: targetUser.id,
        },
      },
      {
        transaction: transaction,
      },
    );

    if (secureInputValues.ban_type === 'nuke') {
      nukedUser = await ban.nuke(targetUser.id, {
        event: currentEvent,
        transaction: transaction,
      });
    }

    await transaction.query('COMMIT');
    await transaction.release();
  } catch (error) {
    await transaction.query('ROLLBACK');
    await transaction.release();
    throw error;
  }

  const secureOutputValues = authorization.filterOutput(userTryingToDelete, 'read:user', nukedUser);

  return response.status(200).json(secureOutputValues);
}
