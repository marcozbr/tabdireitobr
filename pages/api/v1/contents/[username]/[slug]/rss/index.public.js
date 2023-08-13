import nextConnect from 'next-connect';
import controller from 'models/controller.js';
import authorization from 'models/authorization.js';
import cacheControl from 'models/cache-control';
import validator from 'models/validator.js';
import content from 'models/content.js';
import user from 'models/user.js';
import rss from 'models/rss.js';
import webserver from 'infra/webserver.js';

export default nextConnect({
  attachParams: true,
  onNoMatch: controller.onNoMatchHandler,
  onError: controller.onErrorHandler,
})
  .use(controller.injectRequestMetadata)
  .use(controller.logRequest)
  .use(cacheControl.swrMaxAge(10))
  .get(getValidationHandler, getHandler);

function getValidationHandler(request, response, next) {
  const cleanValues = validator(request.query, {
    username: 'required',
    slug: 'required',
  });

  request.query = cleanValues;

  next();
}

async function getHandler(request, response) {
  const userTryingToGet = user.createAnonymous();

  const contentFound = await content.findOne({
    where: {
      owner_username: request.query.username,
      slug: request.query.slug,
      status: 'published',
    },
  });

  if (!contentFound) {
    throw new NotFoundError({
      message: `O conteúdo informado não foi encontrado no sistema.`,
      action: 'Verifique se o "slug" está digitado corretamente.',
      stack: new Error().stack,
      errorLocationCode: 'CONTROLLER:CONTENT:GET_HANDLER:SLUG_NOT_FOUND',
      key: 'slug',
    });
  }

  const secureOutputValues = authorization.filterOutput(userTryingToGet, 'read:content', contentFound);

  const rss2 = rss.generateRss2(
    [secureOutputValues],
    `${webserver.host}/${request.query.username}/${request.query.slug}/rss`
  );

  response.setHeader('Content-Type', 'text/xml; charset=utf-8');
  return response.status(200).send(rss2);
}