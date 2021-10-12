import nextConnect from 'next-connect';
import { v4 as uuid } from 'uuid';
import userFactory from 'models/user.js';
import { InternalServerError, NotFoundError } from '/errors';

const user = userFactory();

export default nextConnect({
        attachParams: true,
        onNoMatch: onNoMatchHandler,
        onError: onErrorHandler,
    })
    .use(injectRequestId)
    .use(authenticationHandler)
    .use(authorizationHandler)
    .get(getHandler)
    .post(postHandler)


async function injectRequestId(request, response, next) {
    request.id = uuid();
    next();
}

async function authenticationHandler(request, response, next) {
    // TODO: implement authentication
    console.log('Trying to authenticate');
    next();
}

async function authorizationHandler(request, response, next) {
    // TODO: implement authorization
    console.log('Trying to authorize');
    next();
}

async function getHandler(request, response) {
    const userList = await user.getUsers();
    return response.status(200).json(userList);
}

async function postHandler(request, response) {
    const returnIdUser = await user.createUser(request.body);
    return response.status(200).json(returnIdUser);
}

async function onNoMatchHandler(request, response) {
    const errorObject = new NotFoundError({ requestId: request.id });
    return response.status(errorObject.statusCode).json(errorObject);
}

function onErrorHandler(error, request, response) {
    const errorObject = new InternalServerError({ requestId: request.id, stack: error.stack });
    return response.status(errorObject.statusCode).json(errorObject);
}