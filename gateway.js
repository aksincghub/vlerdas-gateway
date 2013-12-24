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

// define 2-way SSL/TLS client certificate authorization function
// contains stolen cert logic from from:
// https://github.com/tgies/client-certificate-auth/blob/master/lib/clientCertificateAuth.js
//var authorizeClientCertSubject = function (req, callback) {
var authorizeClientCertSubject = function (req) {
	// see if SSL/TLS-encrypted request has been received
	if(req.connection.encrypted) {
	  // connected with SSL/TLS encryption - perform authorization on requestor from cert.subject.CN		
	  logger.trace("request received has SSL/TLS encryption: testing if valid certificate included and validated at protocol level..."); 
	  // ensure that the certificate was validated at the protocol level
	  if (!req.client.authorized) {
	    var e = new Error('Unauthorized: no Client certificate found - Client certificate required!' +
	                  '(' + req.client.authorizationError + ')');
	    e.status = 401;
	    return e;
	  }

	  // obtain client certificate details
	  logger.trace("attempting to get Client certificate information...");
	  var cert = req.connection.getPeerCertificate();	   
	  if (!cert || !Object.keys(cert).length) {
	    // Handle the bizarre and probably unreal case that a certificate was
	    // validated, but we can't actually inspect it
	    var e = new Error('Client certificate was authenticated, but certificate ' +
	          'information could not be retrieved!');
	    e.status = 500;
	    return e;
	  }

	  // Test the client certificate Subject Common Name value: 
	  // if it evaluates to true and matches a config. values, the request may proceed; 
	  // else return with a 401 Unauthorized response.
	  // attempt to match the given cert.subject.CN value with a config.useClientCertAuth user value	  
	  var certSubjCN = S(cert.subject.CN).trim().s;
	  logger.trace("received and attempting to authorize Client certificate Subject Common Name (CN) value:",certSubjCN);
	  var authenticatedUser = config.useClientCertAuth[certSubjCN];
	  if (authenticatedUser) {
		// have match with the cert. subject, so move onto resource authorization
		// test for allowed method
		logger.trace("attempting to authorize requestor by request method:", req.method);
		if (authenticatedUser.allowMethods === "*" || S(authenticatedUser.allowMethods).contains(req.method)) {
			// test for allowed route
			if (!_.isUndefined(req.parsedUrl.pathname) && req.parsedUrl.pathname!=='/') {
				// have a path
				logger.trace("attempting to authorize requestor to route by request path:", req.parsedUrl.pathname);
				// loop the allowRoutes array to find a match for the given request path
				var isPathMatched = false;
				var i;
		        for (i = 0; i < authenticatedUser.allowRoutes.length; i++) {
		        	if (S(req.parsedUrl.pathname).contains(authenticatedUser.allowRoutes[i])) {
		        		// have a path match! - client is authorized
		        		isPathMatched = true;
		        		// stop looping
		        		break;
		        	}		        	
		        }
		        if (isPathMatched) {
		        	// success, so allow request, do nothing
		        	logger.trace("requestor with cert.Subject.CN="+certSubjCN+" authorized for request method and path");
		        	return null;
		        } else {
		        	// failed allowed routes check - set Unauthorized error
		        	var e = new Error('Unauthorized: Client certificate Subject Common Name value not authorized for request route!');
				    e.status = 401;
				    return e;
		        }		        
			} else {
				// no pathname in request - so allow request for auth. user, do nothing
				// Note: this allows the 404 response to be returned
				logger.trace("requestor with cert.Subject.CN="+certSubjCN+" authorized for a request without a path");
	        	return null;
			}				
		} else {
			// failed allowed methods check - set Unauthorized error
			var e = new Error('Unauthorized: Client certificate Subject Common Name value not authorized for request method!');
		    e.status = 401;
		    return e;
		}	
	  } else {
		// failed cert Subject CN user check - set Unauthorized error  
	    var e = new Error('Unauthorized: Client certificate Subject Common Name value not authorized for VLER Gateway requests!');
	    e.status = 401;
	    return e;
	  }	  
	} else {
		logger.trace("request received has no SSL/TLS encryption..."); 
		// only return this response if there is no HMAC encryption enabled, since HMAC works without encryption
		if(!config.useHMACAuth) {
			// connected without SSL/TLS encryption - return 403 response
			logger.trace('Requestor certificate required for authorization, but 2-way SSL/TLS encryption not enabled for request!');
	        var e = new Error('Forbidden: Requestor certificate required for authorization, but 2-way SSL/TLS encryption not enabled for request!');
		    e.status = 403;
		    return e;
		}
	}   
};

var authorizeHMAC = function (req) {
	logger.trace("Checking HMAC authorization for requestor, method, and URL path..."); 
	// if HMAC signature is valid and requestor is allowed, and is allowed to use the request method and URL path...
	// Note: this is ugly, but this was the best way to use Ofuda, and also pass in the 'req' object for use
    if (!ofuda.validateHttpRequest(req, function validateCredentials(requestAccessKeyId) {
        	var isAuth = false;
        	logger.trace("Checking if user is authorized with HMAC, with given Access Id: " + requestAccessKeyId);    
            var authenticatedUser = config.useHMACAuth[requestAccessKeyId];            
            //logger.trace("Checking HMAC authenticated user configuration, where user found is: " + JSON.stringify(authenticatedUser));
            if (authenticatedUser && (authenticatedUser.allowMethods === "*" || S(authenticatedUser.allowMethods).contains(req.method))) {
            	logger.trace("user found and requestor authorized by HMAC for method");
            	// test for allowed route
    			if (!_.isUndefined(req.parsedUrl.pathname) && req.parsedUrl.pathname!=='/') {
    				// have a path
    				logger.trace("attempting to authorize requestor to route by request path:", req.parsedUrl.pathname);
    				// loop the allowRoutes array to find a match for the given request path
    				var i;
			        for (i = 0; i < authenticatedUser.allowRoutes.length; i++) {
			        	if (S(req.parsedUrl.pathname).contains(authenticatedUser.allowRoutes[i])) {
			        		// have a path match! - client is authorized
			        		logger.trace("requestor authorized by HMAC for a request");
			        		isAuth = true;
			        		// stop looping
			        		break;
			        	}		        	
			        }	   
    			} else {
    				// no pathname in request - so allow request for auth. user, do nothing
    				// Note: this allows the 404 response to be returned
    				logger.trace("requestor authorized by HMAC for a request without a path");
    				isAuth = true;
    			}	            	     			        		
        	}
        	return isAuth ? authenticatedUser : null;	            
    	})
    ) 
    {
    	// HMAC authorization for request failed
    	var e = new Error('Unauthorized: HMAC authorization for request failed!');
	    e.status = 401;	    
	    return e;
    } else {
    	// HMAC authorization for request succeeded
    	return null;
    }
}

// define routing 'handler' function to handle gateway request processing
var handler = function (req, res) {
	logger.info("Received gateway request, where gateway request has method: "+req.method+", host: "+req.headers.host+", and URL: "+req.url);
		
	// set the request transaction id as a UUID and set into req
    req.transactionId = uuid.v4();
    
    // use the request transaction ID to set the temp file 'path' for buffering if needed 
    var path = Path.join(getTempDir(), req.transactionId);
    
    // parse the request URL and place the parsed elements into req   
    if (req.headers && req.headers.host) {    	
    	// put the protocol and hostname into parsed url
    	var protocol;
	    if(req.connection.encrypted) {
	    	protocol = "https://";
	    } else {
	    	protocol = "http://";
	    }
	    req.parsedUrl = url.parse(protocol + req.headers.host + req.url, true);
    } else {
    	// no host header, so do without
    	req.parsedUrl = url.parse(req.url, true);
    }
	logger.trace("Parsed gateway request URL:", req.parsedUrl); 
	
	var isRequestorAuthorized = false;
	// attempt authorization using 2-way SSL/TLS client certificate Subject Common Name value
	var authErr;
	if(config.useClientCertAuth) {
		logger.trace("Checking client SSL/TLS certificate authorization for requestor, method, and URL path..."); 		
    	// use 2-way SSL/TLS Client Certificate Received Authentication/Authorization
    	// - NOTE: SSL/TLS encryption must be present for the req, and a valid client cert received and validated at the Transport level already
		authErr = authorizeClientCertSubject(req);
		if(!authErr) {			
			// is authorized - flag true and do nothing! 				
			isRequestorAuthorized = true;
		} else {
			// if authErr.status is 403 and no SSL on request and config.useHMACAuth is enabled, mark isRequestorAuthorized as false and remove authErr
			if (!req.connection.encrypted && authErr.status == "403" && config.useHMACAuth) {
				isRequestorAuthorized = false;
				authErr = null;
			}
		}
		logger.trace("isRequestorAuthorized from 2-way client cert:",isRequestorAuthorized);
    }	
	
	// if needed, attempt authorization using HMAC Authentication/Source Name Authorization
	if (!isRequestorAuthorized && config.useHMACAuth) {
    	logger.trace("Checking HMAC authorization for requestor, method, and URL path..."); 
    	authErr = authorizeHMAC(req);
    	if(!authErr) {
			// is authorized - flag true and do nothing! 				
			isRequestorAuthorized = true;
		}
    	logger.trace("isRequestorAuthorized from HMAC:",isRequestorAuthorized);
    } 	
	
	// if either authorization enabled, and an error exists 
	if((config.useClientCertAuth || config.useHMACAuth) && authErr) {	
		// output authorization error gateway response
	    logger.trace('Authentication failed:',authErr.message);
        logger.trace('Returning statusCode='+authErr.status+' error gateway response');
        res.writeHead(authErr.status, {
            'Content-Type' : 'text/plain'
        });
        if(authErr.status=="500") {
        	res.end('HTTP 1.1 500/Internal Server Error');
        } else if(authErr.status=="403") {
        	res.end('HTTP 1.1 403/Forbidden');
        } else {
        	res.end('HTTP 1.1 401/Not Authorized');
        }
        return;		
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

    // if not a ping request or a path-less request
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
                    
                    // handle load-balancing if needed
                    var route;
                    if(config.routes[i].options.length > 0) {
                    	// have more than one hostname, port route configured for this route path - do round-robin load-balancing 
                    	// by shifting the config.routes[i].options array for this route path
                    	logger.trace("original config.routes[i].options:",config.routes[i].options);
                    	var route = config.routes[i].options.shift();  
                    	logger.trace("shifted, current route:",route);
                    	config.routes[i].options.push(route);
                    	logger.trace("reset config.routes[i].options:",config.routes[i].options);
                    } else {
                    	// have only one hostname, port configured for this route path - use the one route
                    	route = config.routes[i].options[0];
                    }

                    // set the proxy client request options from config file for this route for proxy_client request call
                    var options = {
                        hostname: route.host,
                        port: route.port,
                        path: req.parsedUrl.path,
                        method: req.method,
                        headers: req.headers,
                    };

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
                        	// Note: called once a socket is assigned to this request and is connected, 
                        	// and no activity occurs on socket for the timeout length
                            proxy_client.setTimeout(route.timeout, function () {
								// Note: if streaming to client has started, this writeHead call will have no effect.
                            	logger.trace('gateway experienced a proxy request time-out to route: '+route.host+':'+route.port+''+req.parsedUrl.path+', returning 504/Gateway Timeout gateway response');                            	  
                                res.writeHead(504, 'Gateway Timeout',{
                                    'Content-Type' : 'text/plain'
                                });
                                res.end('HTTP 1.1 504/Gateway Timeout');
                                socket.destroy();                                
                            });
                        }
                    });

                    // handle error event experienced when processing proxy client request 
                    // - emitted if there was an error connecting to the remote endpoint, 
                    // or while writing or piping data for the stream.writable operations 
                    // for a request body in a POST/PUT request, 
                    // or after a proxy client socket timeout event (above) has occurred,
                    // or?                    
                    proxy_client.on('error', function (err) {
                    	if (res.headersSent) {
                    		// assume response was already sent elsewhere, e.g. Gateway Timeout
                    		logger.trace('error event: but already returned a gateway response');                        
                    	} else {
                    		logger.error('proxy client request error event emitted!, where error: '+err.stack);
                    		if (S(err.message).contains('ECONNREFUSED')) {
                    			// return 503 Service Unavailable, since proxy client is most likely unable to connect to route's host                    			
                    			res.writeHead(503, 'Service Unavailable',{
                                    'Content-Type' : 'text/plain'
                                });
	                    		res.write('There was a communication error with upstream server.');
	                    		res.end('HTTP 1.1 503/Service Unavailable');                 		
                    		} else {                    		
	                            // Note: if streaming to proxy client has started then writeHead call will have no effect.
	                        	// return default error gateway response                     		
	                    		res.writeHead(500, 'Internal Server Error', {
	                                'Content-Type' : 'text/plain'
	                            });
	                    		res.write('There was a communication error with upstream server.');
	                    		res.end('HTTP 1.1 500/Internal Server Error');
                    		}
                    	}
                        // audit the gateway response to the proxy request error:
                    	// perform gateway request, gateway response, proxy error response structured audit logging if config set
                        if (route.audit && route.audit.structured && route.audit.structured.auditRequestResponse) {
                        	logger.trace('Auditing gateway request and response (and proxy client\'s request error)');
                        	logger.trace('res.statusCode:',res.statusCode);
                        	logger.trace("res.headers:",res.headers);
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

                        // get the file size from the http 'Content-Length' header received in proxy client response
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
                                    res.writeHead(500, 'HTTP Header Content-Length does not match received file size, Content-Length:' + fileSize + ' bytes; Uploaded Size: ' + uploadedSize + ' bytes', {
                                        'Content-Type' : 'text/plain'
                                    });
                                    res.end('HTTP 1.1 500/Internal Server Error: HTTP Header Content-Length value does not match received file size.');
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
							res.writeHead(500, 'Internal Server Error', {
                                'Content-Type' : 'text/plain'
                            });
                            res.end('HTTP 1.1 500/Internal Server Error');
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
                                    	logger.error('Could not unlink file:' + path + ', where error: ',err);
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
                        res.writeHead(500, 'Internal Server Error', {
                            'Content-Type' : 'text/plain'
                        });
                        res.end('HTTP 1.1 500/Internal Server Error');   
                    });
                    // have matched the request path to a configured route, so exit the 'for' loop
                    break;
                }
            }
        }
        // handle 'no matching configured route found' case
        if (i === config.routes.length) {
			logger.trace('No matching configured route found for gateway request path!: Returning 404/Not Found gateway response');
            res.writeHead(404, 'Not Found', {
                'Content-Type' : 'text/plain'
            });
            res.end('HTTP 1.1 404/Not Found');
            return;
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
		// return a 404 response to a "no path" request
    	logger.trace('Returning 404/Not Found gateway response, due to receipt of unrecognized type of gateway request');
        res.writeHead(404, 'Not Found');
        res.end('HTTP 1.1 404/Not Found');
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
    
    // normalize the err into JSON to avoid cyclical 
    // JSON object conversion errors and ecrud audit storage errors
    error = {};
    error.errno = err.errno;
    error.message = err.message;
    error.stack = err.stack;

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
    if(!res.headers) {
    	audit.res.headers = res._headers;
    } else {
    	audit.res.headers = res.headers;
    }    
    audit.res.statusCode = res.statusCode;
    audit.res.key = res.key;
    
    audit.res.err = error;

    audit.proxyRes = {};
    audit.proxyRes.headers = proxyRes.headers;
    audit.proxyRes.statusCode = proxyRes.statusCode;
    
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
