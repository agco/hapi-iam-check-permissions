'use strict';

const Boom = require('boom')
const $http = require('http-as-promised')

exports.register = function (server, options, next) {

    let disabled

    var openRoutes = {};
    (options.permissionsToSkip || []).forEach(function (permission) {
        openRoutes[permission] = true
    })


    function onEvaluatePermissionsResponse(res) {
        if (res.statusCode !== 200) {
            console.error('Cannot evaluate permissions. Status code:', res.statusCode, res.payload)
            return Promise.reject(Boom.create(res.statusCode, 'Cannot evaluate permissions', res.payload))
        }
        const payload = JSON.parse(res.payload)
        if (payload.permitted) {
            return Promise.resolve()
        } else {
            return Promise.reject(Boom.forbidden())
        }
    }

    function checkPermissionsLocally(req, applicationId, agcoUuid, permission) {
        return new Promise(function (resolve, reject) {
            const payload = {
                appId: applicationId,
                agcoUuid: agcoUuid,
                name: permission
            }
            const headers = {authorization: req.headers.authorization}
            server.inject({url: options.evaluatePermissionsUrl, method: 'post', payload: payload, headers: headers}, function (res) {
                onEvaluatePermissionsResponse(res).then(resolve, reject)
            })
        })
    }

    function checkPermissionsRemotely(req, applicationId, agcoUuid, permission) {
        const payload = {
            appId: applicationId,
            agcoUuid: agcoUuid,
            name: permission
        }
        const headers = {authorization: req.headers.authorization}
        return $http.post(options.evaluatePermissionsUrl, {headers: headers, body: payload, json: true}).spread(function (res, body) {
            res.payload = JSON.stringify(body)
            return onEvaluatePermissionsResponse(res)
        })
    }

    const parsedEvaluatePermissionsUrl = url.parse(options.evaluatePermissionsUrl)
    const evaluatePermissions = parsedEvaluatePermissionsUrl.protocol ? checkPermissionsRemotely : checkPermissionsLocally

    server.ext('onPostAuth', function (req, reply) {
        if (disabled || !req.auth || !req.auth.isAuthenticated || parsedEvaluatePermissionsUrl.path === req.route.path) {
            reply.continue()
            return
        }
        let permission = req.route.path.replace(/^\//, '').replace(/\//g, '.').replace(/(\{[^}]*\})/g, '*') + '.' + req.method

        function onPermitted() {
            reply.continue()
        }

        function onError(error) {
            if (!error || !error.isBoom) {
                console.error(error && error.stack || error);
            }
            reply(Boom.wrap(error))
        }

        if (openRoutes[permission]) {
            onPermitted()
        } else {
            evaluatePermissions(req, options.applicationId, req.auth && req.auth.credentials && req.auth.credentials.sub, permission).then(onPermitted, onError)
        }
    })

    server.expose('disable', function () {
        disabled = true
    })
    next()
}

exports.register.attributes = {
    pkg: require('../package.json')
}
