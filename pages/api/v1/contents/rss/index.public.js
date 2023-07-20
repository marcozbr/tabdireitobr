import nextConnect from 'next-connect';
import controller from 'models/controller.js';
import authorization from 'models/authorization.js';
import cacheControl from 'models/cache-control';
import user from 'models/user.js';
import rss from 'models/rss';
import content from 'models/content.js';
import webserver from 'infra/webserver.js';
import validator from 'models/validator.js';

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
    page: 'optional',
    per_page: 'optional',
    strategy: 'optional',
  });

  request.query = cleanValues;

  next();
}

async function getHandler(request, response) {
  const userTryingToList = user.createAnonymous();

  const results = await content.findWithStrategy({
    strategy: request.query.strategy,
    where: {
      parent_id: null,
      status: 'published',
    },
    page: request.query.page,
    per_page: request.query.per_page,
  });

  const contentListFound = results.rows;
  const secureContentListFound = authorization.filterOutput(userTryingToList, 'read:content:list', contentListFound);

  const rss2 = rss.generateRss2(
    secureContentListFound,
    `${webserver.host}/${request.query.strategy == 'new' ? 'recentes' : 'relevantes'}/rss`
  );

  response.setHeader('Content-Type', 'text/xml; charset=utf-8');
  response.status(200).send(rss2);
}
