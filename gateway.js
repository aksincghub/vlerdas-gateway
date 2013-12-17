var connect = require("connect");
var config = require('config');
var _ = require('underscore');
var mime = require('mime');
var util = require('util')
var S = require('string');
// Note: included so url.parse will use 
// this to parse the gateway request query string 
var querystring = require('querystring');
var request = require('request');
var url = require('url');
var http = require('http'),       
    https = require('https'),
    crypto = require('crypto'),
    path = require('path');
fs = require('fs');
var Ofuda = require('ofuda');
// initialize the ofuda instance
var ofuda = new Ofuda(config.ofuda);
var uuid = require('node-uuid');
var cluster = require("cluster");
var numCPUs = require('os').cpus().length;
var Path = require('path'), 
    os;
var longjohn = require('longjohn');
var winston = require('winston');
// initialize the logger instance
var logger = getLogger();
module.exports.logger = logger;

// require the 'os' module if possible
try {
    os = require('os');
} catch (e) {
	logger.error("error thrown in require call for \'os\' module, where error:",e);
}

// initially set tmp directory value or re-use 'memorized' tmp directory value 
// for use in storing temporary files in optional file buffering
// Note: memorized tempDir value because those fs.realpathSync() calls are expensive
var tempDir;
function getTempDir() {
    if (!tempDir) {
        if (os && os.tmpDir) {
            tempDir = os.tmpDir();
        } else {
            var environmentVariableNames = ['TMPDIR', 'TMP', 'TEMP'];
            for (var i = 0; i < environmentVariableNames.length; i += 1) {
                var environmentVariableValue = process.env[environmentVariableNames[i]];
                if (environmentVariableValue) {
                    tempDir = fs.realpathSync(environmentVariableValue);
                    break;
                }
            }
            if (!tempDir) {
                if (process.platform === 'win32') {
                    tempDir = fs.realpathSync('c:\\tmp');
                } else {
                    tempDir = fs.realpathSync('/tmp');
                }
            }
        }
    }
    return tempDir;
}

var isAuthorized = function (user) {
	logger.trace("Checking if user is authorized, where user: " + user);    
    return user.allowMethods === "*" || user.allowMethods.indexOf(req.method) >= 0;
};

var validateCredentials = function (requestAccessKeyId) {
	logger.trace("Checking if user is authorized, with Access Id: " + requestAccessKeyId);    
    var authenticatedUser = config.accessControl[requestAccessKeyId];
    logger.trace("Checking authenticated user configuration, where user: " + authenticatedUser);    
    return authenticatedUser !== null && isAuthorized(authenticatedUser) ? authenticatedUser : null;
};

// define routing 'handler' function to handle gateway request processing
var handler = function (req, res) {
	logger.trace("Received gateway request, where gateway request has method: "+req.method+", and URL: "+req.url);

    if (config.accessControl) {
    	logger.trace("Checking Authorization for requestor, method, and URL path...");    
        if (!ofuda.validateHttpRequest(req, validateCredentials)) {  
        	logger.trace('Requestor not authorized');
            logger.trace('Returning 401/Not Authorized gateway response');
            res.writeHead(401)
            res.end('Authorization failed!');
        }
    }

    // ignore favicon request
    if (req.url === '/favicon.ico') {
        logger.trace('Favicon requested');        
        logger.trace('Returning 200/Success gateway response to ignore favicon.ico gateway request');
        res.writeHead(200, {
            'Content-Type' : 'image/x-icon'
        });
        res.end(); 
        return;
    }

    //var path = req.url.replace(/\/([^\/]*)\/?.*$/g, "$1");
    req.transactionId = uuid.v4();
    var path = Path.join(getTempDir(), req.transactionId);
    req.parsedUrl = url.parse(req.url, true);
	logger.trace("Parsed gateway request URL:", req.parsedUrl); 
    if (!_.isUndefined(req.parsedUrl.pathname) && !(S(req.parsedUrl.path).contains('ping') || S(req.parsedUrl.path).contains('PING'))) {
		logger.trace("Attempting to route gateway request..."); 
		// loop through configure routes in config file, and process proxy request if a match is made to the given gateway request path
        var i;
        for (i = 0; i < config.routes.length; i++) {
            if (!_.isUndefined(req.parsedUrl.pathname)) {
                if (S(req.parsedUrl.pathname).contains(config.routes[i].path)) {
                    logger.trace("Matched req.path received to configured routing path, which contains: " + config.routes[i].path);
                	logger.trace("Routing to: " + JSON.stringify(config.routes[i].options), req.parsedUrl.pathname);
                	
                	// throw error if configured route is not defined properly in config file
                    if (_.isUndefined(config.routes[i].options)) {
                        throw new Error("Route's \'options\' has to be defined in configuration file!");
                    }
                    
					// do random routing - set a route only for multiple host/port routes set - in lieu of actual load-balancing
                    var len = Math.floor(Math.random() * config.routes[i].options.length);
                    var route = config.routes[i].options.length > 0 ? config.routes[i].options[len] : config.routes[i].options[0];

                    // set the proxy client request options from config file for this route for proxy_client request call
                    var options = {
                        hostname: route.host,
                        port: route.port,
                        path: req.parsedUrl.path,
                        method: req.method,
                        headers: req.headers,
                    }

                    // define proxy_client and begin proxy http(s) request (asynchronous)
                    // Note: proxy_client will be an instance of type http.ClientRequest
                    var proxy_client;
                    if (!_.isUndefined(route.https)) {
                        options.rejectUnauthorized = route.https.rejectUnauthorized;
                        options.key = route.https.key;
                        options.cert = route.https.cert;
                        options.ca = route.https.ca;
                        options.pfx = route.https.pfx;
                        options.passphrase = route.https.passphrase;
						// must explicitly assign the Agent so the request https options are not ignored by the default Agent
                        options.agent = new https.Agent(options);
                        proxy_client = https.request(options, processRes);
                    } else {
                        proxy_client = http.request(options, processRes);
                    }                    
                    
                    // handle the 'socket' event, which is emitted after a socket is assigned to this request from the socket pool by the Agent
                    proxy_client.on('socket', function (socket) {
                    	logger.trace("proxy client on socket event thrown...");
                        if (!_.isUndefined(route.timeout)) {
                        	logger.trace("setting route.timeout to: "+route.timeout);
                        	// set the explicitly defined timeout, and return a 504 response if the timeout occurs, 
                        	// and release the socket from this request
                        	// Note: called once a socket is assigned to this request and is connected
                            proxy_client.setTimeout(route.timeout, function () {
								// Note: if streaming to client has started, this writeHead call will have no effect.
                            	logger.trace('Experienced a proxy request time-out to route: '+route.host+':'+route.port+''+req.parsedUrl.path+', returning 504/Gateway Timeout gateway response');                            	  
                                res.writeHead(504, 'Gateway Timeout');
                                res.end('The gateway experienced a proxy request time-out.');
                                socket.destroy();                                
                            });
                        }
                    });

                    // handle error event experienced when processing proxy client request 
                    // - emitted if there was an error writing or piping data for the stream.writable operations?
                    proxy_client.on('error', function (err) {
                    	if (res.headersSent) {
                    		// assume response was already sent elsewhere
                    		//logger.trace('already returned a gateway response');                        
                    	} else {
                    		logger.error('proxy client request error event emitted!, where error: '+err);
                            // Note: if streaming to proxy client has started then writeHead call will have no effect.
                        	// return default error gateway response                     		
                    		res.writeHead(500, 'Internal Server Error');
                    		res.write('There was a communication error with upstream server.');
                    		res.end();
                    	}
                        // audit the gateway response to the proxy request error:
                    	// perform gateway request, gateway response, proxy error response structured audit logging if config set
                        if (route.audit && route.audit.structured && route.audit.structured.auditRequestResponse) {
                        	logger.trace('Auditing gateway request and response (and proxy client\'s request error)');
                            audit(route.audit.structured.options, req, res, '', err, function(auditRes) {});
                        }
                        // if file buffering set for this configured route                                         
                        if (route.buffer) {
                            // release the tmp file in the tmp directory                           
                        	fs.exists(path, function (exists) {
                        		if (exists) {
                        			fs.unlink(path, function (err) { 
                                    	if(err) {
                                    		logger.error('Could not unlink file:' + path + ", where error: ",err);
                                    	}
                                    });
                        		}                        		  
                        	});
                        }
                    });

                    logger.trace("Initiating proxy request with options: \n", util.inspect(options)); 

					// define the proxy_client's response-handler callback method
                    // Note: proxyRes is an instance of type http.IncomingMessage
                    function processRes(proxyRes) {
						logger.trace('Handling proxy response received, for proxy request sent with options: ', options); 
                    	
                    	var proxyResponseStatusCode = proxyRes.statusCode;
                    	logger.trace('proxy client request returned proxy response statusCode: ', proxyResponseStatusCode); 
                    	
                        var responseAttachmentAudit;
                        var isResAuditInitialized = false;

                        // get the file size from the http 'Content-Length' received in proxy client response
                        var uploadedSize = 0;
                        var fileSizeStr = proxyRes.headers['content-length'];
                        var fileSize = 0;
                        if (!_.isUndefined(fileSizeStr)) {
                            fileSize = parseInt(fileSizeStr);
                        }

                        // if file buffering set for this configured route
                        if (route.buffer) {
                        	// create write stream named 'file' to the temporary file in tmpdir
                        	// fs.createWriteStream() returns a new stream.Writable object 
                            var file = fs.createWriteStream(path);

                            // where 'file' is a 'stream.writable' instance, 
                            // if a file.write(chunk) call returns false, then the 'drain' event then emitted 
                            // will indicate when it is appropriate to begin writing more data to the stream. 
                            file.on('drain', function () {
                            	// begin writing more data to the stream
                                proxyRes.resume();
                            });
                        }

						// handle proxy client response body when present
                        proxyRes.on('data', function (chunk) {
                            logger.trace('Response data is being written to client, where chunk length (in bytes): ', chunk.length);
                        	//logger.trace('Data:', chunk.toString('utf8'));
                        	
                        	// first time - initialize and perform unstructured audit logging of the proxy response body file if config set
                            if (!isResAuditInitialized && route.audit && route.audit.unstructured && route.audit.unstructured.auditResponse) {
                                var key = req.transactionId + '-RES';
                                res.key = key;
                                logger.trace("Auditing with transaction id: ", key);

                                // initialize and write the first text
                                logger.trace("Initializing response body audit");
                                responseAttachmentAudit = initializeAudit(key, route.audit.unstructured.options);
                                var type = getContentType(proxyRes);
                                var ext = getExtension(type);
                                var beforeAttachmentText = getBeforeAttachment(key, key + '.' + ext, type);
                                logger.trace("Writing before attachment text");//: ", beforeAttachmentText);
                                responseAttachmentAudit.write(beforeAttachmentText, 'binary');
                                isResAuditInitialized = true;
                            }
                            // continue the current unstructured audit logging of the proxy response body file 
                            if (!_.isUndefined(responseAttachmentAudit)) {
                                logger.trace("Writing audit chunk: ");  
                                responseAttachmentAudit.write(chunk, 'binary');
                            }                             
                            // keep track of the actual file size in bytes received for both 
                            // the optional file size verification and optional file 
                            // stream buffering when configured 
                            uploadedSize += chunk.length;
                            // if file buffering set for this configured route
                            if (route.buffer) {
                                uploadProgress = (uploadedSize / fileSize) * 100;
                                logger.trace(Math.round(uploadProgress) + "%" + " downloaded\n");
                                // write some data (i.e. 'chunk') to the underlying system
                                // the return value 'bufferStore' indicates if you 
                                // should continue writing right now or not: if the data had 
                                // to be buffered internally, then '.write()' will return false, else true.
                                // Note: this return value is strictly advisory: it MAY continue 
                                // to write, even if it returns false; however, writes will be buffered 
                                // in memory, so it is best not to do this excessively. Instead, wait 
                                // for the 'drain' event (defined above) before writing more data. 
                                var bufferStore = file.write(chunk);                                
                                if (bufferStore == false) {
                                	// pause writing to the stream to wait for internal memory buffering,
                                	// until the 'drain' event is emmitted to resume writing to the stream
                                    proxyRes.pause();
                                }
                            } else {
                            	// write the binary chunk of the received file without buffering, i.e. directly
                            	// to the gateway response
                                res.write(chunk, 'binary');
                            }
                        });

						// end handling of proxy client response body (when present)
                        proxyRes.on('end', function (data) {
                        	// stop unstructured audit logging of proxy response body if happening (if initialized) 
                            if (isResAuditInitialized && !_.isUndefined(responseAttachmentAudit)) {
                                var endAttachmentText = getEndAttachment(res.key);
                                logger.trace('End chunk write to Audit');//:', endAttachmentText);
                                responseAttachmentAudit.end(endAttachmentText);
                            }
                            logger.trace('End response chunk write to client, returning gateway response from proxy client');       

                            var errState = false;
                            // if file length verification is set for this configured route
                            if (route.strictLength) {
                            	logger.trace('Received file length comparison - Received HTTP header Content-Length value:' + fileSize + ' bytes, received actual file UploadedSize:' + uploadedSize + ' bytes');
                            	// if HTTP header Content-Length value does not match the actual file size received 
                                if (fileSize != uploadedSize) {
                                	// return an error gateway response, set errState to true
                                	logger.error('HTTP Header Content-Length does not match received file size, Content-Length:' + fileSize + ' bytes; Uploaded Size: ' + uploadedSize + ' bytes');
                                    res.writeHead(500, 'HTTP Header Content-Length does not match received file size, Content-Length:' + fileSize + ' bytes; Uploaded Size: ' + uploadedSize + ' bytes');
                                    res.end('HTTP Header Content-Length value does not match received file size.');
                                    errState = true;
                                }
                            }
                            // if file buffering set for this configured route
                            if (route.buffer) {
                                if (!errState) {
                                	// write the buffered file received to the gateway response stream,
                                	// now that buffering has completed without error, and 
                                	// pass through the proxy response headers received
                                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                                    fs.createReadStream(path).pipe(res);
                                }
                                // release the tmp file in the tmp directory
                                fs.unlink(path, function (err) { 
                                    if(err) {
                                    	logger.error('Could not unlink file:' + path + ", where error: ",err);
                                    }
                                });
                            } else { // no file buffering
                            	// if no errors occurred
                                if (!errState) {
                                	// mark the gateway response as complete
                                    res.end();
                                }
                            }
                            // perform gateway request, gateway response, proxy response structured audit logging if config set
                            if (route.audit && route.audit.structured && route.audit.structured.auditRequestResponse) {
                            	logger.trace('Auditing gateway request and response (and proxy client\'s proxyRes)');//, req, res);
                                audit(route.audit.structured.options, req, res, proxyRes, '', function(auditRes) {});
                            }
                        });

						// handle error experienced when processing proxy client response body (when present)
                        proxyRes.on('error', function (e) {
                            logger.error('Error emitted from proxy client request attempt, where error: ', e);
							logger.trace('Returning 500/Internal Server Error gateway response due to proxy client error');
							// TODO: Should this error information be returned in the gateway response?
                            res.writeHead(500, e);
                            res.end('Internal Server Error Occured');
                            // stop unstructured audit logging of proxy response attachment received if occurring 
                            if (isResAuditInitialized && !_.isUndefined(responseAttachmentAudit)) {
                                logger.trace('End response chunk write to Audit, where error: ' + e);                                
                            	logger.trace('End response chunk write to Audit');//: ', endAttachmentText);   
                                var endAttachmentText = getEndAttachment(res.key);
                                responseAttachmentAudit.end(endAttachmentText);
                            }
                            // perform gateway request, gateway response, proxy response, and proxy response processing error structured audit logging if config set
                            if (route.audit && route.audit.structured && route.audit.structured.auditRequestResponse) {
								logger.trace('Auditing gateway request and response (and proxy client\'s proxyRes, and proxy client\'s error)');//, req, res);  
                                audit(route.audit.structured.options, req, res, proxyRes, e, function(auditRes) {});
                            }
                            // if file buffering set for this configured route
                            if (route.buffer) {
                            	// release the tmp file in the tmp directory
                            	fs.unlink(path, function (err) { 
                                    if(err) {
                                    	logger.error('Could not unlink file:' + path + ", where error: ",err);
                                    }
                                });
                            }
                        });
                        
                        // if file buffering set for this configured route
                        if (route.buffer) {
                            // Allow empty config
                        } else { // no file buffering
                        	// write the gateway response headers using the proxy response headers
                            res.writeHead(proxyRes.statusCode, proxyRes.headers);
                        }
                    }

                    var isReqAuditInitialized = false;
                    var requestAttachmentAudit;

					// handle gateway request body (when present)
                    req.on('data', function (chunk) {
                        logger.trace('Writing to server, where chunk length:', chunk.length);
                    	//logger.trace('Data: ' + chunk.toString('utf8'));

                        // first time - initialize and perform unstructured audit logging of the gateway request body file if config set
                        if (!isReqAuditInitialized && route.audit && route.audit.unstructured && route.audit.unstructured.auditRequest) {
                            var key = req.transactionId + '-REQ';
                            req.key = key;
                            var type = getContentType(req);
                            var ext = getExtension(type);
                            logger.trace("Auditing with transaction id: ", key);  
                            // initialize and write the first text
                            logger.trace("Initializing audit: ");       
                            requestAttachmentAudit = initializeAudit(key, route.audit.unstructured.options);
                            var beforeAttachmentText = getBeforeAttachment(key, key + '.' + ext, type);
                            logger.trace("Writing before attachment text");//: ", beforeAttachmentText);  
                            requestAttachmentAudit.write(beforeAttachmentText, 'binary');
                            isReqAuditInitialized = true;
                        }
                        // continue the current unstructured audit logging of the gateway request body file (if initialized)
                        if (!_.isUndefined(requestAttachmentAudit)) {
                            logger.trace("Writing audit chunk"); 
                            requestAttachmentAudit.write(chunk, 'binary');
                        }
                        // write the next chunk of the binary stream of the gateway request body file received to the proxy client
                        //logger.trace("Writing proxy client chunk: ", chunk);
                        proxy_client.write(chunk, 'binary');
                    });

					// end handling gateway request body (when present)
                    req.on('end', function () {
                    	// stop unstructured audit logging of gateway request body if happening (if initialized)
                        if (isReqAuditInitialized && !_.isUndefined(requestAttachmentAudit)) {
                            var endAttachmentText = getEndAttachment(req.key);
                            logger.trace('End chunk write to audit');//: ', endAttachmentText); 
                            requestAttachmentAudit.end(endAttachmentText);
                        }
                        logger.trace('End chunk write to server'); 
                        // stop the proxy_client
                        proxy_client.end();
                    });

					// handle error experienced when processing gateway request body (when present)
                    req.on('error', function (e) {
                        logger.error('Problem with gateway request, request error event emitted: ', e);
                        // stop unstructured audit logging of gateway request body if happening
                        if (isReqAuditInitialized && !_.isUndefined(requestAttachmentAudit)) {
                            var endAttachmentText = getEndAttachment(req.key);
                            logger.trace('End chunk write to audit');//: ', endAttachmentText);
                            requestAttachmentAudit.end(endAttachmentText);
                        }
                        // stop the proxy_client
                        proxy_client.end();
                        // return an error gateway response
                        logger.trace('Returning 500/Internal Server Error gateway response, due to gateway request data processing error Event');
                        res.writeHead(500, 'Internal Server Error');
                        res.end('Internal Server Error');   
                    });
                    // have matched the request path to a configured route, so exit the 'for' loop
                    break;
                }
            }
        }
        // handle 'no matching configured route found' case
        if (i === config.routes.length) {
			logger.trace('No matching configured route found for gateway request path!: Returning 404/Not Found gateway response');
            res.writeHead(404, 'Not Found');
            res.end('Not Found');
        } 
    } else if (S(req.parsedUrl.path).contains('ping') || S(req.parsedUrl.path).contains('PING')) {
		// return the "PONG" response to a ping request
        var pongResponse = 'PONG!' + '\nVA VLER Gateway received \'/ping\' request headers:\n' + JSON.stringify(req.headers, true, 2) + '\n';
        //+ '\nGateway response time: '+ res +' ms\n';
        var resLength = pongResponse.length;
        logger.trace('Returning 200 PONG gateway response, with body: ',pongResponse);
        res.writeHead(200, {
            'Content-Type': 'text/plain',
            'Content-Length': resLength
        });
        res.write(pongResponse);
        res.end();
        return;
    } else {
		// return a 404 response to an missing or unknown path request
    	logger.trace('Returning 404/Not Found gateway response, due to receipt of unrecognized type of gateway request');
        res.writeHead(404, 'Not Found');
        res.end('Not Found');
        return;
    }
};

function getExtension(type) {
    var ext = mime.extension(type);
    ext = ext ? ext : 'dat';
    logger.trace('Getting extension for type:', type, ' extension:', ext);
    return ext;
}

function getContentType(req) {
    var type = req.headers["content-type"] ? req.headers["content-type"] : "application/octlet-stream";
    logger.trace('Getting type value from content-type in req.headers: ', req.headers["content-type"], ' type:' + type);
    return type;
}

function getBeforeAttachment(key, filename, type) {
    var beforeRequestAttachment = new Buffer(
            '------' + key + '\r\n' +
            'Content-Disposition: form-data; name="file"; filename="' + filename + '"' + '\r\n' +
            'Content-Type: ' + type + '\r\n' +
            '\r\n');
    //logger.trace('Getting before request attachment: ', beforeRequestAttachment);
    return beforeRequestAttachment;
}

function getEndAttachment(key) {
    var endRequestAttachment = new Buffer(
            '\r\n' +
            '------' + key + '--' + '\r\n');
    //logger.trace('Getting end request attachment: ', endRequestAttachment);    
    return endRequestAttachment;
}

function getAttachmentHeader(key) {
    var requestAttachmentHeader = {
        "Content-Type": "multipart/form-data; boundary=----" + key
    };
    logger.trace('Getting request attachment header: ', requestAttachmentHeader);    
    return requestAttachmentHeader;
}

function getAttachmentAuditOptions(key, auditOptions) {
    var header = getAttachmentHeader(key);
    var options = auditOptions ? auditOptions : {};
    options.headers = header;
    logger.trace('Getting attachment audit options: ', options);    
    return options;
}

// initialize unstructured audit logging 
function initializeAudit(key, options) {
    // these are the post options
	logger.trace('Initializing audit for transaction id: ', key);
    requestAttachmentAudit = http.request(getAttachmentAuditOptions(key, options));

    requestAttachmentAudit.on('error', function (e) {
        logger.error('Problem with request attachment audit, where error: ' + e);
    });
    
    requestAttachmentAudit.on('end', function () {
    	logger.trace('End request attachment audit write to service');        
    });

    return requestAttachmentAudit;
}

// 'fix' security options in configOptions parameter
function configureOptions(configOptions) {
	logger.trace("Fixing server SSL options");//, configOptions);    
    var options = {};
    options.https = {};

    logger.trace("Fixing SSL key: ", JSON.stringify(configOptions.https.key));
    
    if (!_.isUndefined(configOptions.https.key) && _.isString(configOptions.https.key)) {
    	logger.trace("Loading SSL key file: ", configOptions.https.key);        
        options.https.key = fs.readFileSync(configOptions.https.key);
    }

    if (!_.isUndefined(configOptions.https.cert) && _.isString(configOptions.https.cert)) {
    	logger.trace("Loading SSL cert file: ", configOptions.https.cert);        
        options.https.cert = fs.readFileSync(configOptions.https.cert);
    }

    if (!_.isUndefined(configOptions.https.pfx) && _.isString(configOptions.https.pfx)) {
    	logger.trace("Loading SSL pfx file: ", configOptions.https.pfx);        
        options.https.pfx = fs.readFileSync(configOptions.https.pfx);
    }

    options.https.requestCert = configOptions.https.requestCert;
    options.https.rejectUnauthorized = configOptions.https.rejectUnauthorized;
    options.https.agent = configOptions.https.agent;

    if (!_.isUndefined(configOptions.https.ca) && Array.isArray(configOptions.https.ca)) {
        options.https.ca = [];
        for (var i = 0; i < configOptions.https.ca.length; i++) {
        	logger.trace("Loading SSL ca file: ", configOptions.https.ca[i]);            
            options.https.ca[i] = fs.readFileSync(configOptions.https.ca[i]);
        }
    }

    options.https.passphrase = configOptions.https.passphrase;
    return options;
}

// load and 'fix' all gateway security options from config file
if (config.secureServer) {
	logger.trace("Have gateway secure server options configuration loaded from file");//: ", config.secureServer.options);
    var options = configureOptions(config.secureServer.options);
 	logger.trace("Fixed gateway secure server options configuration");//: ", options);
}

// load and 'fix' all security options from config file for each configured route
for (var i = 0; i < config.routes.length; i++) {
    for (var j = 0; j < config.routes[i].options.length; j++) {
        if (config.routes[i].options[j].https) {
            config.routes[i].options[j].https = configureOptions(config.routes[i].options[j]).https;
        }
    }
}

// define connect middleware
var app = connect();
// create stream object to redirect connect.logger into Winston.logger instead of stdout
var winstonStream = {
	    write: function(message, encoding){
	        logger.info(message);
	    }
	};
// enable the X-Response-Time to be calculated and set in all gateway responses
app.use(connect.responseTime());
// set the connect Logger and redirect into winston logger with this format
app.use(connect.logger({stream:winstonStream, format:'"To Remote-Addr:" :remote-addr "For Req.Host:" :req[host] "For Req:" :method :url HTTP/:http-version "Req.Accept:" :req[Accept] "Res.Content-Type:" :res[Content-Type] "Res.Status:" :status "Res.Content-Length:" :res[Content-Length] bytes "Referer:" :referrer "User-Agent:" :user-agent "Gateway Response Time:" :response-time ms'}));
// set the 'handler' function
app.use(handler);

// set up the cluster, server, begin listening for gateway requests 
if (cluster.isMaster) {
	// this is the cluster master, so perform clustering initialization:
    // fork cluster workers
    for (var i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    cluster.on('fork', function(worker) {
    	logger.info('A worker was forked with #: ' + worker.id);    
    });
 //   cluster.on('online', function (worker) {       
 //       logger.info('A worker is now running with #: ' + worker.id);        
 //   });
    cluster.on('listening', function (worker, address) {        
    	logger.info('A worker #'+worker.id+' is now connected to: ' + address.address + ':' + address.port);        
    });
    cluster.on('disconnect', function (worker) {        
    	logger.info('A worker #'+worker.id+' is now disconnected');        
    });
    cluster.on('exit', function (worker, code, signal) {
    	logger.info('worker #: ' + worker.process.pid + ' died');        
    });
} else {
	// this is a cluster worker, so initialize http/https server instance(s) 
	// from config options using connect 'app' middleware with 'handler' function set
    var httpsServer;
    if (config.secureServer) {
    	httpsServer = https.createServer(options.https, app).listen(config.secureServer.port, config.secureServer.host, function () {
           logger.info("Gateway listening on Secure Port: ", config.secureServer.port, " Host: ", config.secureServer.host);
    	});
    }
    var httpServer = http.createServer(app).listen(config.server.port, config.server.host, function () {
       logger.info("Gateway listening on Port: ", config.server.port, " Host: ", config.server.host);
    });   
}

// define the structured audit logging function
function audit(options, req, res, proxyRes, err, callback) {
    var auditService = http.request(options, function(auditRes) {
        auditRes.on('data', function(chunk) {
            logger.trace('Write to audit client, with chunk length: ', chunk.length);
        });

        auditRes.on('end', function(data) {
            logger.trace('End chunk audit write to client');
        });

        auditRes.on('error', function(e) {
            logger.error('Error with audit, where error: ', e);
        });
    });

    req = req ? req : {};
    res = res ? res : {};
    proxyRes = proxyRes ? proxyRes : {};

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

    audit.proxyRes = {};
    audit.proxyRes.headers = proxyRes.headers;
    audit.res.statusCode = proxyRes.statusCode;


    var auditStr = JSON.stringify(audit);
    logger.trace("Auditing: " + auditStr); 
    auditService.write(auditStr, 'binary');
    auditService.end();
}

// define default exception handler event
process.on('uncaughtException', function (err) {
    logger.error('Caught exception: ' + err.stack);
    process.exit(1);
});

// define process Ctrl-C Shutdown event
process.on('SIGINT', function () {
	logger.info('Shutting down from SIGINT (Crtl-C)');
    process.exit();
});

// define process exit event
process.on('exit', function (err) {
    if (err) {
    	logger.error('Exiting with error... Error: ', err);
    } else {
        logger.info('Exiting...');
    }
});

// create and set the winston logger instance
function getLogger() {
	var consoleOptions = {"level": config.log.console.level,"silent": config.log.console.silent,"colorize": config.log.console.colorize,"timestamp": config.log.console.timestamp, "label": config.log.console.label};
	var fileOptions = {"level": config.log.file.level,"silent": config.log.file.silent,"colorize": config.log.file.colorize,"timestamp": config.log.file.timestamp,"label": config.log.file.label,"filename": config.log.file.filename, "maxsize": config.log.file.maxSize,"maxFiles": config.log.file.maxFiles,"json": config.log.file.json};
	var logger = new (winston.Logger)({
		// set the custom log levels
		levels: config.logger.levels,
	    transports: [
	      new (winston.transports.Console)(consoleOptions),
	      new (winston.transports.File)(fileOptions)
	    ]
	});
	// set the custom log colors for the levels
	winston.addColors(config.logger.colors);
	return logger;
}
