import nextConnect from 'next-connect';

import { NotFoundError } from 'errors';
import cacheControl from 'models/cache-control';
import content from 'models/content';
import controller from 'models/controller';
import validator from 'models/validator';
import viewsContent from 'models/views-content';

export default nextConnect({
  attachParams: true,
  onNoMatch: controller.onNoMatchHandler,
  onError: controller.onErrorHandler,
})
  .use(controller.injectRequestMetadata)
  .use(controller.logRequest)
  .use(cacheControl.swrMaxAge(60))
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
  const contentFound = await content.findOne({
    where: {
      owner_username: request.query.username,
      slug: request.query.slug,
      status: 'published',
    },
  });

  if (!contentFound) {
    throw new NotFoundError({
      message: `Este conteúdo não está disponível.`,
      action: 'Verifique se o "slug" está digitado corretamente ou considere o fato do conteúdo ter sido despublicado.',
      stack: new Error().stack,
      errorLocationCode: 'CONTROLLER:CONTENT:VIEWS:GET_HANDLER:SLUG_NOT_FOUND',
      key: 'slug',
    });
  }

  const getViews = await viewsContent.get(contentFound);

  response.statusCode = 200;
  response.setHeader('Content-Type', 'application/json');
  response.end(JSON.stringify(getViews));
}
