import { ForbiddenError, ValidationError } from 'errors';
import validator from 'models/validator.js';

const availableFeatures = new Set([
  // USER
  'create:user',
  'read:user',
  'read:user:self',
  'update:user',

  // MIGRATION
  'read:migration',
  'create:migration',

  // ACTIVATION_TOKEN
  'read:activation_token',

  // RECOVERY_TOKEN
  'read:recovery_token',

  // EMAIL_CONFIRMATION_TOKEN
  'read:email_confirmation_token',

  // SESSION
  'create:session',
  'read:session',

  // CONTENT
  'read:content',
  'update:content',
  'create:content',
  'create:content:text_root',
  'create:content:text_child',
  'read:content:list',
  'read:content:tabcoins',

  // SPONSORED CONTENT
  'create:sponsored_content',
  'read:sponsored_content',
  'read:sponsored_content:list',
  'read:sponsored_content:tabcoins',

  // MODERATION
  'read:user:list',
  'read:votes:others',
  'update:content:others',
  'update:user:others',
  'ban:user',
  'create:recovery_token:username',
]);

function can(user, feature, resource) {
  validateUser(user);
  validateFeature(feature);

  if (!user.features.includes(feature)) return false;

  switch (feature) {
    case 'update:user':
      return resource?.id && user.id === resource.id;

    case 'update:content':
      return (resource?.owner_id && user.id === resource.owner_id) || user.features.includes('update:content:others');
  }

  if (!resource) return true;

  return false;
}

function filterInput(user, feature, input, target) {
  validateUser(user);
  validateFeature(feature);
  validateInput(input);

  let filteredInputValues = {};

  if (feature === 'create:session' && can(user, feature)) {
    filteredInputValues = {
      email: input.email,
      password: input.password,
    };
  }

  if (feature === 'create:user' && can(user, feature)) {
    filteredInputValues = {
      username: input.username,
      email: input.email,
      password: input.password,
    };
  }

  if (feature === 'update:user' && can(user, feature, target)) {
    filteredInputValues = {
      username: input.username,
      email: input.email,
      password: input.password,
      description: input.description,
      notifications: input.notifications,
    };
  }

  if (feature === 'update:user:others' && can(user, feature)) {
    filteredInputValues = {
      description: input.description,
    };
  }

  if (feature === 'ban:user' && can(user, feature)) {
    filteredInputValues = {
      ban_type: input.ban_type,
    };
  }

  if (feature === 'read:activation_token' && can(user, feature)) {
    filteredInputValues = {
      tokenId: input.token_id,
    };
  }

  if (feature === 'create:content:text_root' && can(user, feature)) {
    filteredInputValues = {
      slug: input.slug,
      title: input.title,
      body: input.body,
      status: input.status,
      source_url: input.source_url,
    };
  }

  if (feature === 'create:content:text_child' && can(user, feature)) {
    filteredInputValues = {
      parent_id: input.parent_id,
      slug: input.slug,
      title: input.title,
      body: input.body,
      status: input.status,
      source_url: input.source_url,
    };
  }

  if (feature === 'create:sponsored_content' && can(user, feature)) {
    filteredInputValues = {
      slug: input.slug,
      title: input.title,
      body: input.body,
      source_url: input.source_url,
      deactivate_at: input.deactivate_at,
      tabcash: input.tabcash,
    };
  }

  if (feature === 'update:content' && can(user, feature, target)) {
    filteredInputValues = {
      parent_id: input.parent_id,
      slug: input.slug,
      title: input.title,
      body: input.body,
      status: input.status,
      source_url: input.source_url,
    };
  }

  // Force the clean up of "undefined" values
  return JSON.parse(JSON.stringify(filteredInputValues));
}

function filterOutput(user, feature, output) {
  validateUser(user);
  validateFeature(feature);
  validateOutput(output);

  let filteredOutputValues = {};

  if (feature === 'read:session' && can(user, feature)) {
    if (user.id && output.user_id && user.id === output.user_id) {
      filteredOutputValues = {
        id: output.id,
        expires_at: output.expires_at,
        created_at: output.created_at,
        updated_at: output.updated_at,
      };
    }
  }

  if (feature === 'create:session' && can(user, feature)) {
    if (user.id && output.user_id && user.id === output.user_id) {
      filteredOutputValues = {
        id: output.id,
        token: output.token,
        expires_at: output.expires_at,
        created_at: output.created_at,
        updated_at: output.updated_at,
      };
    }
  }

  if (feature === 'read:user') {
    filteredOutputValues = {
      id: output.id,
      username: output.username,
      description: output.description,
      features: output.features,
      tabcoins: output.tabcoins,
      tabcash: output.tabcash,
      created_at: output.created_at,
      updated_at: output.updated_at,
    };
  }

  if (feature === 'read:user:self') {
    if (user.id && output.id && user.id === output.id) {
      filteredOutputValues = {
        id: output.id,
        username: output.username,
        email: output.email,
        description: output.description,
        notifications: output.notifications,
        features: output.features,
        tabcoins: output.tabcoins,
        tabcash: output.tabcash,
        created_at: output.created_at,
        updated_at: output.updated_at,
      };
    }
  }

  if (feature === 'read:user:list') {
    filteredOutputValues = output.map((user) => ({
      id: user.id,
      username: user.username,
      description: user.description,
      features: user.features,
      tabcoins: user.tabcoins,
      tabcash: user.tabcash,
      created_at: user.created_at,
      updated_at: user.updated_at,
    }));
  }

  if (feature === 'read:activation_token') {
    filteredOutputValues = {
      id: output.id,
      used: output.used,
      expires_at: output.expires_at,
      created_at: output.created_at,
      updated_at: output.updated_at,
    };
  }

  if (feature === 'read:content') {
    const clonedOutput = { ...output };
    const allowedStatus = ['published', 'sponsored'];
    const isDeactivated = output.deactivate_at && output.deactivate_at < new Date();

    if ((!allowedStatus.includes(output.status) && user.id !== output.owner_id) || isDeactivated) {
      clonedOutput.title = '[Não disponível]';
      clonedOutput.body = '[Não disponível]';
      clonedOutput.slug = 'nao-disponivel';
      clonedOutput.source_url = null;
      clonedOutput.children_deep_count = 0;
    }

    filteredOutputValues = validator(clonedOutput, {
      content: 'required',
    });
  }

  if (feature === 'read:sponsored_content') {
    filteredOutputValues = validator(output, {
      sponsored_content: 'required',
    });
  }

  if (feature === 'read:content:tabcoins') {
    filteredOutputValues = validator(output, {
      tabcoins: 'required',
      tabcoins_credit: 'required',
      tabcoins_debit: 'required',
    });
  }

  if (feature === 'read:sponsored_content:tabcoins') {
    filteredOutputValues = validator(output, {
      tabcoins: 'required',
    });
  }

  if (feature === 'read:content:list') {
    filteredOutputValues = output.map((content) => {
      return validator(content, {
        content: 'required',
      });
    });
  }

  if (feature === 'read:sponsored_content:list') {
    filteredOutputValues = output.map((content) => {
      return validator(content, {
        sponsored_content_complete: 'required',
      });
    });
  }

  if (feature === 'read:recovery_token') {
    filteredOutputValues = validator(output, {
      used: 'required',
      expires_at: 'required',
      created_at: 'required',
      updated_at: 'required',
    });
  }

  if (feature === 'read:email_confirmation_token') {
    filteredOutputValues = validator(output, {
      id: 'required',
      used: 'required',
      expires_at: 'required',
      created_at: 'required',
      updated_at: 'required',
    });
  }

  // Force the clean up of "undefined" values
  return JSON.parse(JSON.stringify(filteredOutputValues));
}

function validateUser(user) {
  if (!user) {
    throw new ValidationError({
      message: `Nenhum "user" foi especificado para a ação de autorização.`,
      action: `Contate o suporte informado o campo "errorId".`,
    });
  }

  if (!user.features || !Array.isArray(user.features)) {
    throw new ValidationError({
      message: `"user" não possui "features" ou não é um array.`,
      action: `Contate o suporte informado o campo "errorId".`,
    });
  }
}

function validateFeature(feature) {
  if (!feature) {
    throw new ValidationError({
      message: `Nenhuma "feature" foi especificada para a ação de autorização.`,
      action: `Contate o suporte informado o campo "errorId".`,
    });
  }

  if (!availableFeatures.has(feature)) {
    throw new ValidationError({
      message: `A feature utilizada não está disponível na lista de features existentes.`,
      action: `Contate o suporte informado o campo "errorId".`,
      context: {
        feature: feature,
      },
    });
  }
}

function validateInput(input) {
  if (!input) {
    throw new ValidationError({
      message: `Nenhum "input" foi especificado para a ação de filtro.`,
      action: `Contate o suporte informado o campo "errorId".`,
    });
  }
}

function validateOutput(output) {
  if (!output) {
    throw new ValidationError({
      message: `Nenhum "output" foi especificado para a ação de filtro.`,
      action: `Contate o suporte informado o campo "errorId".`,
    });
  }
}

function canRequest(feature) {
  return function (request, response, next) {
    const userTryingToRequest = request.context.user;

    if (!userTryingToRequest.features.includes(feature)) {
      throw new ForbiddenError({
        message: `Usuário não pode executar esta operação.`,
        action: `Verifique se este usuário possui a feature "${feature}".`,
        errorLocationCode: 'MODEL:AUTHORIZATION:CAN_REQUEST:FEATURE_NOT_FOUND',
      });
    }

    next();
  };
}

export default Object.freeze({
  can,
  canRequest,
  filterOutput,
  filterInput,
});
