var config = require('config');
var _ = require('underscore');
var mime = require('mime');
var S = require('string');
var querystring = require('querystring');
var request = require('request');
var url = require('url');
var http = require('http'),
path = require('path'),
https = require('https'),
crypto = require('crypto')
    fs = require('fs');
var Ofuda = require('ofuda');
var ofuda = new Ofuda(config.ofuda);
var uuid = require('node-uuid');
var cluster = require("cluster");
var numCPUs = require('os').cpus().length;

var isAuthorized = function (user) {
    if (config.debug) {
        console.log("Checking if user is authorized " + user);
    }
    return user.allowMethods === "*" || user.allowMethods.indexOf(req.method) >= 0;
};
var validateCredentials = function (requestAccessKeyId) {
    if (config.debug) {
        console.log("Checking if user is authorized with Access Id: " + requestAccessKeyId);
    }
    var authenticatedUser = config.accessControl[requestAccessKeyId];
    if (config.debug) {
        console.log("Checking authenticated user configuration " + authenticatedUser);
    }
    return authenticatedUser !== null && isAuthorized(authenticatedUser) ? authenticatedUser : null;
};

//------------------------
// Routing Handler
//------------------------
var handler = function (req, res) {

    if (config.debug) {
        console.log("Received Request", req);
        console.log("Parsing URL", req.url);
        console.log("Checking Authorization", req.method);
    }

    if (config.accessControl) {
        if (!ofuda.validateHttpRequest(req, validateCredentials)) {
            if (config.debug) {
                console.error("Not Authorized");
            }
            res.writeHead(401)
            res.end('Authorization failed!');
        }
    }

    // ignore favicon
    if (req.url === '/favicon.ico') {
        res.writeHead(200, {
            'Content-Type' : 'image/x-icon'
        });
        res.end();
        if (config.debug) {
            console.log('Favicon requested');
        }
        return;
    }

    //var path = req.url.replace(/\/([^\/]*)\/?.*$/g, "$1");
    req.transactionId = uuid.v4();
    req.parsedUrl = url.parse(req.url, true);
    if (config.debug) {
        console.log("Parsed URL", req.parsedUrl);
    }
    if (req.parsedUrl.query && req.parsedUrl.query.redirectURL) {
        if (config.debug) {
            console.log("Checking if there is a redirect URL", req.parsedUrl.query.redirectURL);
        }
        if (req.parsedUrl.query.redirectURL) {
            if (config.debug) {
                console.log("Parsing Redirect URL", req.parsedUrl.query.redirectURL);
            }
            var redirect = url.parse(req.parsedUrl.query.redirectURL);
            if (config.debug) {
                console.log("Parsed Redirect URL", redirect);
            }
            if (config.debug) {
                console.log("Redirecting to ", redirect.href);
            }
            // Only HTTP is supported
            request.get(req.parsedUrl.query.redirectURL).pipe(res);
            if (config.debug) {
                console.log("Auditing Request and Response", req, res);
            }
            audit(req, res, '', function (auditRes) {});
            return;

        } else {
            if (config.debug) {
                console.log("Problem with parsing Redirect URL", url);
            }
        }
    } else if (!_.isUndefined(req.parsedUrl.pathname) && !(S(req.parsedUrl.path).contains('ping') || S(req.parsedUrl.path).contains('PING'))) {
        if (config.debug) {
            console.log("Routing..");
        }
        for (var i = 0; i < config.routes.length; i++) {
            var route = config.routes[i];
            if (!_.isUndefined(req.parsedUrl.pathname)) {
                if (S(req.parsedUrl.pathname).contains(config.routes[i].path)) {
                    if (config.debug) {
                        console.log("Routing Path contains " + config.routes[i].path);
                        console.log("Routing to " + config.routes[i].host, config.routes[i].port, req.parsedUrl.pathname);
                    }

                    var options = {
                        hostname : config.routes[i].host,
                        port : config.routes[i].port,
                        path : req.parsedUrl.path,
                        method : req.method,
                        headers : req.headers
                    };

                    if (config.debug) {
                        console.log("Initiating Proxy Request with options:", options);
                    }

                    var proxy_client = http.request(options, function (proxyRes) {

                            if (config.debug) {
                                console.log('Sending request ', options);
                            }

                            var responseAttachmentAudit;
                            var isResAuditInitialized = false;
                            proxyRes.on('data', function (chunk) {
                                if (config.debug) {
                                    console.log('Response Data is being written to client, Chunk Length:', chunk.length);
                                    console.log('Data:', chunk.toString('utf8'));

                                }
                                if (!isResAuditInitialized && config.audit.unstructured.auditResponse) {
                                    var key = req.transactionId + '-RES';
                                    res.key = key;
                                    if (config.debug) {
                                        console.log("Auditing with Transaction: ", key);
                                    }
                                    // Initialize and write the first text
                                    if (config.debug) {
                                        console.log("Initializing Audit: ");
                                    }
                                    responseAttachmentAudit = initializeAudit(key);
                                    var type = getContentType(proxyRes);
                                    var ext = getExtension(type);
                                    var beforeAttachmentText = getBeforeAttachment(key, key + '.' + ext, type);
                                    if (config.debug) {
                                        console.log("Writing Before Attachment Text: ", beforeAttachmentText);
                                    }
                                    responseAttachmentAudit.write(beforeAttachmentText, 'binary');
                                    isResAuditInitialized = true;
                                }
                                if (!_.isUndefined(responseAttachmentAudit)) {
                                    if (config.debug) {
                                        console.log("Writing Audit Chunk");
                                    }
                                    responseAttachmentAudit.write(chunk, 'binary');
                                }
                                if (config.debug) {
                                    console.log("Writing Client Chunk: ", chunk);
                                }
                                res.write(chunk, 'binary');
                            });

                            proxyRes.on('end', function (data) {
                                if (isResAuditInitialized && !_.isUndefined(responseAttachmentAudit)) {
                                    var endAttachmentText = getEndAttachment(res.key);
                                    if (config.debug) {
                                        console.log('End chunk write to Audit:', endAttachmentText);
                                    }
                                    responseAttachmentAudit.end(endAttachmentText);
                                }
                                if (config.debug) {
                                    console.log('End chunk write to client');
                                }
                                res.end();
                                if (config.debug) {
                                    console.log('Auditing Request and Response', req, res);
                                }
                                audit(req, res, '', function (auditRes) {});
                            });

                            proxyRes.on('error', function (e) {
                                console.error('Error with client ', e);
                                res.writeHead(404, 'Not Found');
                                res.end();
                                if (isResAuditInitialized && !_.isUndefined(responseAttachmentAudit)) {
                                    if (config.debug) {
                                        console.log('End chunk write to Audit with Error:' + e);
                                    }
                                    if (config.debug) {
                                        console.log('End chunk write to Audit:', endAttachmentText);
                                    }
                                    var endAttachmentText = getEndAttachment(res.key);
                                    responseAttachmentAudit.end(endAttachmentText);
                                }
                                if (config.debug) {
                                    console.log('Auditing Request and Response:', req, res);
                                }
                                audit(req, res, e, function (auditRes) {});
                            });
                            res.writeHead(proxyRes.statusCode, proxyRes.headers);
                        });

                    var isReqAuditInitialized = false;
                    var requestAttachmentAudit;

                    req.on('data', function (chunk) {
                        if (config.debug) {
                            console.log('Write to server ', chunk.length);
                            console.log('Data:' + chunk.toString('utf8'));
                        }

                        // First time
                        if (!isReqAuditInitialized && config.audit.unstructured.auditRequest) {
                            var key = req.transactionId + '-REQ';
                            req.key = key;
                            var type = getContentType(req);
                            var ext = getExtension(type);
                            if (config.debug) {
                                console.log("Auditing with Transaction: ", key);
                            }
                            // Initialize and write the first text
                            if (config.debug) {
                                console.log("Initializing Audit: ");
                            }
                            requestAttachmentAudit = initializeAudit(key);
                            var beforeAttachmentText = getBeforeAttachment(key, key + '.' + ext, type);
                            if (config.debug) {
                                console.log("Writing Before Attachment Text: ", beforeAttachmentText);
                            }
                            requestAttachmentAudit.write(beforeAttachmentText, 'binary');
                            isReqAuditInitialized = true;
                        }
                        if (!_.isUndefined(requestAttachmentAudit)) {
                            if (config.debug) {
                                console.log("Writing Audit Chunk");
                            }
                            requestAttachmentAudit.write(chunk, 'binary');
                        }
                        if (config.debug) {
                            console.log("Writing Proxy Client Chunk: ", chunk);
                        }
                        proxy_client.write(chunk, 'binary');
                    });

                    req.on('end', function () {
                        //if (config.debug) {
                        //}
                        if (isReqAuditInitialized && !_.isUndefined(requestAttachmentAudit)) {
                            var endAttachmentText = getEndAttachment(req.key);
                            if (config.debug) {
                                console.log('End chunk write to Audit:', endAttachmentText);
                            }
                            requestAttachmentAudit.end(endAttachmentText);
                        }
						if(config.debug) {
							console.log('End chunk write to server');
						}
                        proxy_client.end();
                    });

                    req.on('error', function (e) {
                        if (config.debug) {
                            console.error('Problem with request ', e);
                        }
                        if (isReqAuditInitialized && !_.isUndefined(requestAttachmentAudit)) {
                            var endAttachmentText = getEndAttachment(req.key);
                            if (config.debug) {
                                console.log('End chunk write to Audit:', endAttachmentText);
                            }
                            requestAttachmentAudit.end(endAttachmentText);
                        }
                        proxy_client.end();
                        res.writeHead(404, 'Not Found');
                        res.end();
                    });
                    break;
                }
            }
        }
    } else if (S(req.parsedUrl.path).contains('ping') || S(req.parsedUrl.path).contains('PING')) {
        if (config.debug) {
            console.log("Sending PONG..");
        }
        res.writeHead(200, {
            'Content-Type' : 'text/plain'
        });
        res.write('PONG' + '\n' + JSON.stringify(req.headers, true, 2));
        res.end();
        return;
    } else {
        if (config.debug) {
            console.log("Sending Error 404..");
        }
        res.writeHead(404, 'Not Found');
        res.end();
        return;
    }

};

function getExtension(type) {
    var ext = mime.extension(type);
    ext = ext ? ext : 'dat';
    if (config.debug) {
        console.log('Getting extension for type:', type, ' extension:', ext);
    }

    return ext;
}

function getContentType(req) {
    var type = req.headers["content-type"] ? req.headers["content-type"] : "application/octlet-stream";
    if (config.debug) {
        console.log('Getting type from ', req.headers["content-type"], ' type:' + type);
    }

    return type;
}

function getBeforeAttachment(key, filename, type) {
    var beforeRequestAttachment = new Buffer(
            '------' + key + '\r\n' +
            'Content-Disposition: form-data; name="file"; filename="' + filename + '"' + '\r\n' +
            'Content-Type: ' + type + '\r\n' +
            '\r\n');
    if (config.debug) {
        console.log('Getting Before Attachment: ', beforeRequestAttachment);
    }

    return beforeRequestAttachment;
}

function getEndAttachment(key) {
    var endRequestAttachment = new Buffer(
            '\r\n' +
            '------' + key + '--' + '\r\n');
    if (config.debug) {
        console.log('Getting End Attachment: ', endRequestAttachment);
    }
    return endRequestAttachment;
}

function getAttachmentHeader(key) {
    var requestAttachmentHeader = {
        "Content-Type" : "multipart/form-data; boundary=----" + key
    };
    if (config.debug) {
        console.log('Getting Attachment Header: ', requestAttachmentHeader);
    }
    return requestAttachmentHeader;
}

function getAttachmentAuditOptions(key) {
    var header = getAttachmentHeader(key);
    var options = config.audit.unstructured.options;
    options.headers = header;
    if (config.debug) {
        console.log('Getting Attachment Audit options: ', options);
    }
    return options;
}

function initializeAudit(key) {
    //These are the post options
    if (config.debug) {
        console.log('Initializing audit for id: ', key);
    }

    requestAttachmentAudit = http.request(getAttachmentAuditOptions(key));

    requestAttachmentAudit.on('error', function (e) {
        console.error('Problem with request attachment audit: ' + e);
    });
    requestAttachmentAudit.on('end', function () {
        if (config.debug) {
            console.log('End request attachemnt audit write to server');
        }
    });
    return requestAttachmentAudit;

}

function configureOptions(configOptions) {
    if (config.debug) {
        console.log("Fixing Options:", configOptions);
    }
    var options = {};
    options.https = {};

    if (config.debug) {
        console.log("Fixing Key:", JSON.stringify(configOptions.https.key));
    }
    if (!_.isUndefined(configOptions.https.key) && _.isString(configOptions.https.key)) {
        if (config.debug) {
            console.log("Loading key file:", configOptions.https.key);
        }
        options.https.key = fs.readFileSync(configOptions.https.key);
    }

    if (!_.isUndefined(configOptions.https.cert) && _.isString(configOptions.https.cert)) {
        if (config.debug) {
            console.log("Loading Cert file:", configOptions.https.cert);
        }
        options.https.cert = fs.readFileSync(configOptions.https.cert);
    }

    if (!_.isUndefined(configOptions.https.pfx) && _.isString(configOptions.https.pfx)) {
        if (config.debug) {
            console.log("Loading PFX file:", configOptions.https.pfx);
        }
        options.https.pfx = fs.readFileSync(configOptions.https.pfx);
    }

    options.https.requestCert = true;
    options.https.rejectUnauthorized = configOptions.https.rejectUnauthorized;
    options.https.agent = configOptions.https.agent;
    options.https.ca = [];
    for (var i = 0; i < configOptions.https.ca.length; i++) {
        if (config.debug) {
            console.log("Loading file:", configOptions.https.ca[i]);
        }
        options.https.ca[i] = fs.readFileSync(configOptions.https.ca[i]);
    }
    options.https.passphrase = configOptions.https.passphrase;
    return options;
}

if (config.debug) {
    console.log("Server Configuration from file:", config.secureServer.options);
}
var options = configureOptions(config.secureServer.options);
if (config.debug) {
    console.log("Server Configuration:", options);
}

if (cluster.isMaster) {
    // Fork workers.
    for (var i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('online', function (worker) {
        if (config.debug) {
            console.log('A worker with #' + worker.id);
        }
    });
    cluster.on('listening', function (worker, address) {
        if (config.debug) {
            console.log('A worker is now connected to ' + address.address + ':' + address.port);
        }
    });
    cluster.on('exit', function (worker, code, signal) {
        if (config.debug) {
            console.log('worker ' + worker.process.pid + ' died');
        }
    });
} else {
    https.createServer(options.https, handler).listen(config.secureServer.port, config.secureServer.host);
    http.createServer(handler).listen(config.server.port, config.server.host);

    if (config.debug) {
        console.log("Proxy listening on Port:", config.server.port, ' Host:', config.server.host);
        console.log("Proxy listening on Port:", config.secureServer.port, ' Host:', config.secureServer.host);
    }
}

function audit(req, res, err, callback) {
    var auditService = http.request(config.audit.structured.options, function (auditRes) {
            auditRes.on('data', function (chunk) {
                if (config.debug) {
                    console.log('Write to audit client ', chunk.length);
                }
            });

            auditRes.on('end', function (data) {
                if (config.debug) {
                    console.log('End chunk audit write to client');
                }
            });

            auditRes.on('error', function (e) {
                console.error('Error with audit ', e);
            });

        });

    var audit = {};
    audit.transactionId = req.transactionId;
    audit.req = {}
    audit.req.url = req.url;
    audit.req.parsedUrl = req.parsedUrl;
    audit.req.headers = req.headers;
    audit.req.method = req.method;
    audit.req.httpVersion = req.httpVersion;
    audit.req.trailers = req.trailers;
    audit.req.remoteAddress = req.connection.remoteAddress;
    audit.req.key = req.key;

    audit.res = {};
    audit.res.headers = res.headers;
    audit.res.statusCode = res.statusCode;
    audit.res.key = res.key;
    audit.res.err = err;

    var auditStr = JSON.stringify(audit);
    if (config.debug) {
        console.log("Auditing:" + auditStr);
    }
    auditService.write(auditStr, 'binary');
    auditService.end();
}

// Default exception handler
process.on('uncaughtException', function (err) {
    console.error('Caught exception: ' + err);
});
// Ctrl-C Shutdown
process.on('SIGINT', function () {
    console.log('Shutting down from  SIGINT (Crtl-C)');
    process.exit()
})
// Default exception handler
process.on('exit', function (err) {
    console.log('Exiting.. Error:', err);
});
